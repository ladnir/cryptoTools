#include "WolfSSL_Tests.h"


extern "C" {
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <../wolfssl/IDE/WIN10/user_settings.h>
}
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif
#include <array>
#include <stdio.h>
#include <iostream>
#include <thread>

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Log.h>

using namespace oc;



namespace osuCrypto
{
    enum class WolfSSL_errc
    {
        success = 0,
        unknown = 1
    };
}
namespace boost {
    namespace system {
        template <>
        struct is_error_code_enum<osuCrypto::WolfSSL_errc> : true_type {};
    }
}

namespace { // anonymous namespace

    struct WolfSSLErrCategory : boost::system::error_category
    {
        const char* name() const noexcept override
        {
            return "osuCrypto_WolfSSL";
        }

        std::string message(int err) const override
        {
            std::array<char, WOLFSSL_MAX_ERROR_SZ> buffer;
            return wolfSSL_ERR_error_string(err, buffer.data());
        }
    };

    const WolfSSLErrCategory WolfSSLCategory{};

} // anonymous namespace

namespace osuCrypto
{
    inline error_code make_error_code(WolfSSL_errc e)
    {
        return { static_cast<int>(e), WolfSSLCategory };
    }
}


struct WolfSocket
{
    void LOG(std::string X) {
        if (wolfSSL_is_server(mSSL) == false)
            lout << Color::Red << "client " << (X) << std::endl << Color::Default;
        else
            lout << Color::Green << "server " << (X) << std::endl << Color::Default;
        mLog.push(X);
    }


    boost::asio::ip::tcp::socket mSock;
    boost::asio::strand<boost::asio::io_context::executor_type> mStrand;
    boost::asio::io_context& mIos;
    WOLFSSL* mSSL = nullptr;
    oc::Log mLog;

    WolfSocket(boost::asio::io_context& ios, WOLFSSL_CTX* ctx)
        : mSock(ios)
        , mStrand(ios.get_executor())
        , mIos(ios)
        , mSSL(wolfSSL_new(ctx))
    {
        //oc::lout << "client chl " << std::hex << u64(writeCtx) << std::endl;
        wolfSSL_SetIOWriteCtx(mSSL, this);
        wolfSSL_SetIOReadCtx(mSSL, this);
    }
    WolfSocket(WolfSocket&&) = delete;
    WolfSocket(const WolfSocket&) = delete;

    ~WolfSocket()
    {
        wolfSSL_free(mSSL);
        mSSL = nullptr;
        TODO("call wolf shutdown");
        //error_code ec;
        //close(ec);
    }

    std::vector<boost::asio::mutable_buffer> mSendBufs, mRecvBufs;
    u64 mSendBufIdx = 0, mRecvBufIdx = 0;
    struct WolfState
    {
        enum class Phase
        {
            Uninit,
            Connect,
            Accept,
            Normal,
            Closed
        };
        Phase mPhase = Phase::Uninit;
        span<char> mPendingSendBuf;
        span<char> mPendingRecvBuf;

        bool hasPendingSend() { return mPendingSendBuf.size() > 0; }
        bool hasPendingRecv() { return mPendingRecvBuf.size() > 0; }
    };

    WolfState mState;

    u64 mSendBT, mRecvBT;
    error_code mSendEC, mRecvEC, mSetupEC;

    std::function<void(const error_code&, u64)> mSendCB, mRecvCB;
    std::function<void(const error_code&)> mSetupCB, mShutdownCB;


    bool hasRecvBuffer() { return mRecvBufIdx < mRecvBufs.size(); }
    boost::asio::mutable_buffer& curRecvBuffer() { return mRecvBufs[mRecvBufIdx]; }

    bool hasSendBuffer() { return mSendBufIdx < mSendBufs.size(); }
    boost::asio::mutable_buffer& curSendBuffer() { return mSendBufs[mSendBufIdx]; }

    void send(
        span<boost::asio::mutable_buffer> buffers,
        error_code& ec,
        u64& bt)
    {
        std::promise<void> prom;
        async_send(buffers, [&](const error_code& ecc, u64 btt) {
            ec = ecc;
            bt = btt;
            prom.set_value(); });
        prom.get_future().get();
    }

    void async_send(
        span<boost::asio::mutable_buffer> buffers,
        const std::function<void(const error_code&, u64)>& fn)
    {
        std::stringstream ss;
        ss << "async_send ";
        for (auto b : buffers)
            ss << b.size() << " ";
        LOG(ss.str());

        if (mSendBufs.size())
            throw RTE_LOC;

        mSendCB = fn;
        mSendBufs.insert(mSendBufs.end(), buffers.begin(), buffers.end());
        mSendBufIdx = 0;

        sendNext();
    }

    void sendNext()
    {
        LOG("sendNext");
        assert(hasSendBuffer());

        boost::asio::dispatch(mStrand, [this]() {

            auto buf = (char*)curSendBuffer().data();
            auto size = curSendBuffer().size();

            int err = 0, ret = 0;
            auto wasPending = mState.hasPendingSend();

            // this will call sslRequextSendCB(...)
            ret = wolfSSL_write(mSSL, buf, size);
            if (ret <= 0)
            {
                err = wolfSSL_get_error(mSSL, 0);
                if (err == WOLFSSL_ERROR_WANT_WRITE)
                {
                    assert(mState.hasPendingSend() == true);
                }
                else
                {
                    assert(err);
                    mSendEC = make_error_code(WolfSSL_errc(err));
                    mSendCB(mSendEC, mSendBT);
                }
            }
            else
            {
                if (ret == size)
                {

                    ++mSendBufIdx;
                    if (hasSendBuffer())
                    {
                        LOG("next send buffer");
                        sendNext();
                    }
                    else
                    {
                        mSendBufIdx = 0;
                        mSendBufs.resize(0);
                        mSendCB(mSendEC, mSendBT);
                        mSendBT = 0;
                    }
                }
                else
                {
                    LOG("redo send buffer");
                    curSendBuffer() = boost::asio::mutable_buffer(buf + ret, size - ret);
                    sendNext();
                }
            }
             
            });

    }

    int sslRquestSendCB(char* buf, int size)
    {
        LOG("sslRquestSendCB " + std::string(mState.hasPendingRecv() ? "complete" : "init"));

        assert(mStrand.running_in_this_thread());

        if (mState.hasPendingSend() == false)
        {
            mState.mPendingSendBuf = { buf, size };
            boost::asio::mutable_buffer b(buf, size);
            boost::asio::async_write(mSock, b, [this](const error_code& ec, u64 bt) {
                boost::asio::dispatch(mStrand, [this, ec, bt]() {
                    LOG("data Sent : " + std::to_string(bt) + " bytes");

                    mSendEC = ec;
                    mSendBT += bt;

                    assert(mState.hasPendingSend());

                    int ret, err;

                    switch (mState.mPhase)
                    {
                    case WolfState::Phase::Normal:
                    {
                        sendNext();
                        break;
                    }
                    case WolfState::Phase::Connect:
                    {
                        connectNext();
                        break;
                    }
                    case WolfState::Phase::Accept:
                    {
                        acceptNext();
                        break;
                    }
                    default:
                        std::terminate();
                    }
                    }
                );
                }
            );

            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }
        else
        {
            if (mSendEC)
                return WOLFSSL_CBIO_ERR_GENERAL;
            assert(mState.mPendingSendBuf.data() == buf && mState.mPendingSendBuf.size() == size);
            mState.mPendingSendBuf = {};
            return size;
        }

    }

    void recv(
        span<boost::asio::mutable_buffer> buffers,
        error_code& ec,
        u64& bt)
    {
        std::promise<void> prom;
        async_recv(buffers, [&](const error_code& ecc, u64 btt) {
            ec = ecc;
            bt = btt;
            prom.set_value(); });
        prom.get_future().get();
    }

    void async_recv(
        span<boost::asio::mutable_buffer> buffers,
        const std::function<void(const error_code&, u64)>& fn)
    {

        std::stringstream ss;
        ss << "async_recv ";
        for (auto b : buffers)
            ss << b.size() << " ";
        LOG(ss.str());

        if (mRecvBufs.size())
            throw RTE_LOC;

        mRecvCB = fn;
        mRecvBufs.insert(mRecvBufs.end(), buffers.begin(), buffers.end());
        mRecvBufIdx = 0;

        recvNext();
    }

    void recvNext()
    {
        LOG("recvNext");

        boost::asio::dispatch(mStrand, [this]() {

            assert(hasRecvBuffer());

            auto buf = (char*)curRecvBuffer().data();
            auto size = curRecvBuffer().size();

            int err = 0, ret = 0;
            auto wasPending = mState.hasPendingRecv();

            // this will call sslRequextRecvCB(...)
            ret = wolfSSL_read(mSSL, buf, size);

            if (ret <= 0)
            {
                err = wolfSSL_get_error(mSSL, 0);
                assert(err);
                if (err == WOLFSSL_ERROR_WANT_READ)
                {
                    assert(mState.hasPendingRecv() == true);
                    // no op
                }
                else
                {
                    mRecvEC = make_error_code(WolfSSL_errc(err));
                    mRecvCB(mRecvEC, mRecvBT);
                }
            }
            else
            {
                if (ret == size)
                {
                    ++mRecvBufIdx;
                    if (hasRecvBuffer())
                    {
                        LOG("next recv buffer");
                        recvNext();
                    }
                    else
                    {
                        mRecvBufIdx = 0;
                        mRecvBufs.resize(0);
                        mRecvCB(mRecvEC, mRecvBT);
                        mRecvBT = 0;
                    }
                }
                else
                {
                    // update the current buffer to point to what is left...
                    LOG("redo recv buffer");
                    curRecvBuffer() = boost::asio::mutable_buffer(buf + ret, size - ret);
                    recvNext();
                }
            }
            }
        );
    }

    int sslRquestRecvCB(char* buf, int size)
    {
        LOG("sslRquestRecvCB " + std::string(mState.hasPendingRecv() ? "complete" : "init"));

        assert(mStrand.running_in_this_thread());

        if (mState.hasPendingRecv() == false)
        {
            mState.mPendingRecvBuf = { buf,  size };
            boost::asio::mutable_buffer b(buf, size);
            boost::asio::async_read(mSock, b, [this](const error_code& ec, u64 bt) {
                boost::asio::dispatch(mStrand, [this, ec, bt]() {
                    LOG("data recvd: " + std::to_string(bt) + " bytes");

                    mRecvEC = ec;
                    mRecvBT += bt;

                    assert(mState.hasPendingRecv());

                    int ret, err;

                    switch (mState.mPhase)
                    {
                    case WolfState::Phase::Normal:
                    {
                        recvNext();
                        break;
                    }
                    case WolfState::Phase::Connect:
                    {
                        connectNext();
                        break;
                    }
                    case WolfState::Phase::Accept:
                    {
                        acceptNext();
                        break;
                    }
                    default:
                        std::terminate();
                    }
                    }
                );
                }
            );
            return WOLFSSL_CBIO_ERR_WANT_READ;
        }
        else
        {
            if (mRecvEC)
                return WOLFSSL_CBIO_ERR_GENERAL;
            assert(mState.mPendingRecvBuf.data() == buf && mState.mPendingRecvBuf.size() == size);
            mState.mPendingRecvBuf = {};
            return size;
        }
    }

    void connect(
        const boost::asio::ip::tcp::endpoint& addr,
        error_code& ec)
    {
        std::promise<error_code> prom;
        async_connect(addr, [&prom](const error_code& ec) { prom.set_value(ec); });
        ec = prom.get_future().get();
    }

    void async_connect(
        const boost::asio::ip::tcp::endpoint& addr,
        std::function<void(const error_code&)>&& cb)
    {
        LOG("async_connect");

        assert(mState.mPhase == WolfState::Phase::Uninit);
        mState.mPhase = WolfState::Phase::Connect;
        mSetupCB = std::move(cb);

        mSock.async_connect(addr, [this](const error_code& ec) {
            if (ec)
            {
                mSendEC = ec;
                mRecvEC = ec;
                mSetupCB(ec);
            }
            else
            {
                connectNext();
            }
            }
        );
    }


    void connectNext()
    {
        LOG("connectNext");
        boost::asio::dispatch(mStrand, [this]() {

            assert(mState.mPhase == WolfState::Phase::Connect);

            int ret, err = 0;
            ret = wolfSSL_connect(mSSL);
            if (ret != WOLFSSL_SUCCESS)
                err = wolfSSL_get_error(mSSL, 0);

            if (ret == WOLFSSL_SUCCESS) {
                mState.mPhase = WolfState::Phase::Normal;
                mSetupCB(mSetupEC);
            }
            else if (
                err != WOLFSSL_ERROR_WANT_READ &&
                err != WOLFSSL_ERROR_WANT_WRITE)
            {
                std::cout << make_error_code(WolfSSL_errc(err)).message() << std::endl;

                bool ioError = false;
                if (mState.hasPendingSend())
                {
                    assert(mSendEC);
                    mSetupEC = mSendEC;
                    ioError = true;
                }
                else if (mState.hasPendingRecv())
                {
                    assert(mRecvEC);
                    mSetupEC = mRecvEC;
                    ioError = true;
                }
                else
                {
                    mSetupEC = make_error_code(WolfSSL_errc(ret));
                }
                mSetupCB(mSendEC);
            }
            }
        );
    }

    void accept(
        boost::asio::ip::tcp::acceptor& accpt,
        error_code& ec)
    {
        std::promise<error_code> prom;
        async_accept(accpt, [&prom](const error_code& ec) {
            prom.set_value(ec);
            }
        );
        ec = prom.get_future().get();
    }

    void async_accept(
        boost::asio::ip::tcp::acceptor& accpt,
        std::function<void(const error_code&)>&& cb)
    {
        LOG("async_accept");
        assert(mState.mPhase == WolfState::Phase::Uninit);
        mState.mPhase = WolfState::Phase::Accept;
        mSetupCB = std::move(cb);

        accpt.async_accept(mSock, [this](const error_code& ec) {
            if (ec)
            {
                mSetupCB(ec);
            }
            else
                acceptNext();
            }
        );
    }

    void acceptNext()
    {
        LOG("acceptNext");
        boost::asio::dispatch(mStrand, [this]() {

            assert(mState.mPhase == WolfState::Phase::Accept);

            int ret, err = 0;
            ret = wolfSSL_accept(mSSL);
            if (ret != WOLFSSL_SUCCESS)
                err = wolfSSL_get_error(mSSL, 0);

            if (ret == WOLFSSL_SUCCESS) {
                mState.mPhase = WolfState::Phase::Normal;
                mSetupCB(mSetupEC);
            }
            else if (
                err != WOLFSSL_ERROR_WANT_READ &&
                err != WOLFSSL_ERROR_WANT_WRITE)
            {
                bool ioError = false;
                if (mState.hasPendingSend())
                {
                    assert(mSendEC);
                    mSetupEC = mSendEC;
                    ioError = true;
                }
                else if (mState.hasPendingRecv())
                {
                    assert(mRecvEC);
                    mSetupEC = mRecvEC;
                    ioError = true;
                }
                else
                {
                    mSetupEC = make_error_code(WolfSSL_errc(err));
                }
                mSetupCB(mSendEC);
            }
            }
        );
    }

    //void close(error_code& ec)
    //{
    //    LOG("close");

    //    std::promise<void> prom;
    //    async_close([this, &ec, &prom](const error_code& ecc) {
    //        ec = ecc;
    //        prom.set_value();
    //        }
    //    );

    //    prom.get_future().get();
    //}

    //void async_close(std::function<void(const error_code&)>&& fn)
    //{
    //    mShutdownCB = std::move(fn);
    //    
    //    closeNext();
    //}

    //void closeNext()
    //{
    //    boost::asio::dispatch(mStrand, [this]() mutable {

    //        assert(mState.hasPendingRecv() == false && mState.hasPendingSend() == false);

    //        if (mState.mPhase == WolfState::Phase::Uninit ||
    //            mState.mPhase == WolfState::Phase::Closed)
    //        {
    //            error_code ec;
    //            mSock.close();
    //            auto cb = std::move(mShutdownCB);
    //            cb(ec);
    //        }
    //        else if(
    //            mState.mPhase == WolfState::Phase::Accept ||
    //            mState.mPhase == WolfState::Phase::Connect)
    //        {

    //        }

    //        if (mSSL)
    //        {

    //            else if (mState.mPhase == WolfState::Phase::Normal)
    //            {

    //            }

    //            wolfSSL_shutdown(mSSL);
    //            wolfSSL_free(mSSL);
    //            mSSL = nullptr;

    //        }
    //        }
    //    );
    //}

    static int recvCallback(WOLFSSL* ssl, char* buf, int size, void* ctx)
    {
        //lout << "in recv cb with " << std::hex << u64(ctx) << std::endl;
        WolfSocket& sock = *(WolfSocket*)ctx;
        assert(sock.mSSL == ssl);
        return sock.sslRquestRecvCB(buf, size);
    }

    static int sendCallback(WOLFSSL* ssl, char* buf, int size, void* ctx)
    {
        //lout << "in send cb with " << std::hex << u64(ctx) << std::endl;
        WolfSocket& sock = *(WolfSocket*)ctx;
        assert(sock.mSSL == ssl);
        return sock.sslRquestSendCB(buf, size);
    }
};




/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////


int client()
{
    WOLFSSL_METHOD* method = wolfSSLv23_client_method();
    auto ctx = wolfSSL_CTX_new(method);

    CallbackIORecv rcb = WolfSocket::recvCallback;
    CallbackIOSend scb = WolfSocket::sendCallback;
    wolfSSL_SetIOSend(ctx, scb);
    wolfSSL_SetIORecv(ctx, rcb);

    if (wolfSSL_CTX_load_verify_locations(ctx, caCertFile, 0) != WOLFSSL_SUCCESS)
        err_sys("can't load ca file, Please run from wolfSSL home dir");

    IOService ios;
    boost::asio::ip::tcp::resolver resolver(ios.mIoService);
    boost::asio::ip::tcp::resolver::query query("127.0.0.1", "1212");
    boost::asio::ip::tcp::endpoint addr = *resolver.resolve(query);

    WolfSocket sock(ios.mIoService, ctx);
    error_code ec;
    u64 bt;
    sock.connect(addr, ec);
    if (ec)
        throw std::runtime_error(ec.message());
    lout << Color::Red << u64(&sock) << " connect " << std::endl << Color::Default;

    std::array<char, WOLFSSL_MAX_ERROR_SZ> buffer;
    std::array<char, sizeof(int)> sizeBuf;
    std::array<char, 1024> msg;
    std::array<char, 1025> reply;

    while (fgets(msg.data(), sizeof(msg), stdin) != 0) {

        auto sendSz = (int)XSTRLEN(msg.data());

        boost::asio::mutable_buffer bufs[2];
        bufs[0] = boost::asio::mutable_buffer((char*)&sendSz, sizeof(int));
        bufs[1] = boost::asio::mutable_buffer(msg.data(), sendSz);
        sock.send(bufs, ec, bt);
        lout << Color::Red << u64(&sock) << " sent " << std::endl << Color::Default;

        if (ec)
            throw std::runtime_error(ec.message());



        if (strncmp(msg.data(), "quit", 4) == 0) {
            fputs("sending server shutdown command: quit!\n", stdout);
            break;
        }

        if (strncmp(msg.data(), "break", 5) == 0) {
            fputs("sending server session close: break!\n", stdout);
            break;
        }


        sock.recv({ &bufs[1], 1 }, ec, bt);
        lout << Color::Red << u64(&sock) << " recv " << std::endl << Color::Default;

        if (ec)
            throw std::runtime_error(ec.message());
    }

    //sock.close();
    wolfSSL_CTX_free(ctx);

    //CloseSocket(sockfd);

    return 0;
}


int server()
{

    SOCKET_T       sockfd = 0;
    WOLFSSL_METHOD* method = 0;
    WOLFSSL_CTX* ctx = 0;

    int    ret = 0;
    int    doDTLS = 0;
    int    outCreated = 0;
    int    shutDown = 0;
    int    useAnyAddr = 0;
    word16 port;
    char   buffer[WOLFSSL_MAX_ERROR_SZ];

    port = wolfSSLPort;

    IOService ios;
    boost::asio::ip::tcp::resolver resolver(ios.mIoService);
    boost::asio::ip::tcp::resolver::query query("127.0.0.1", "1212");
    boost::asio::ip::tcp::endpoint addr = *resolver.resolve(query);
    boost::asio::ip::tcp::acceptor accpt(ios.mIoService);

    error_code ec;
    accpt.open(addr.protocol());
    accpt.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    accpt.bind(addr, ec);
    accpt.listen(boost::asio::socket_base::max_connections);

    if (ec)
    {
        lout << "ec bind " << ec.message() << std::endl;
        throw RTE_LOC;
    }

    method = wolfSSLv23_server_method();
    ctx = wolfSSL_CTX_new(method);
    CallbackIORecv rcb = WolfSocket::recvCallback;
    CallbackIOSend scb = WolfSocket::sendCallback;
    wolfSSL_SetIOSend(ctx, scb);
    wolfSSL_SetIORecv(ctx, rcb);



#define SVR_COMMAND_SIZE 256

    while (!shutDown) {

        std::array<char, SVR_COMMAND_SIZE> command;
        int     echoSz = 0;

        WolfSocket sock(ios.mIoService, ctx);
        wolfSSL_SetTmpDH_file(sock.mSSL, dhParamFile, WOLFSSL_FILETYPE_PEM);

        sock.accept(accpt, ec);
        if (ec)
        {
            std::cout << "accept failed: " << ec.message() << std::endl;
            continue;
        }
        lout << Color::Green << u64(&sock) << " accepted " << std::endl << Color::Default;

        u64 bt;

        boost::asio::mutable_buffer bufs[1];

        while (true)
        {
            bufs[0] = boost::asio::mutable_buffer((char*)&echoSz, sizeof(int));
            sock.recv(bufs, ec, bt);

            lout << Color::Green << u64(&sock) << " recvd size " << std::endl << Color::Default;


            if (ec)
            {
                std::cout << Color::Green << "recv failed: " << ec.message() << std::endl << Color::Default;
                break;
            }

            if (echoSz > command.size())
            {
                std::cout << Color::Green << "msg too large. " << std::endl << Color::Default;
                break;
            }

            bufs[0] = boost::asio::mutable_buffer(command.data(), echoSz);
            sock.recv(bufs, ec, bt);

            lout << Color::Green << u64(&sock) << " recvd body " << std::endl << Color::Default;

            if (strncmp(command.data(), "quit", 4) == 0) {
                printf("client sent quit command: shutting down!\n");
                shutDown = 1;
                break;
            }
            else if (strncmp(command.data(), "break", 5) == 0) {
                printf("client sent break command: closing session!\n");
                break;
            }
            else if (strncmp(command.data(), "GET", 3) == 0) {
                const char resp[] =
                    "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n"
                    "<html><body BGCOLOR=\"#ffffff\"><pre>\r\n"
                    "greetings from wolfSSL\r\n</body></html>\r\n\r\n";

                echoSz = (int)strlen(resp) + 1;
                bufs[0] = boost::asio::mutable_buffer(command.data(), echoSz);
                strncpy(command.data(), resp, command.size());
            }
            else
            {
                command[echoSz] = 0;
                lout << Color::Yellow << command.data() << std::endl;
            }

            sock.send(bufs, ec, bt);
            if (ec)
            {
                std::cout << "failed to send. " << ec.message() << std::endl;
            }

            lout << Color::Green << u64(&sock) << " sent body " << std::endl << Color::Default;
        }

    }
    wolfSSL_CTX_free(ctx);
    lout << Color::Green << " server exit " << std::endl << Color::Default;

    return 0;
}

void wolf_demo(const osuCrypto::CLP& cmd)
{

    //StartTCP();

    auto thrd = std::thread([] { server(); });

    std::this_thread::sleep_for(std::chrono::seconds(1));
    client();


    thrd.join();
}