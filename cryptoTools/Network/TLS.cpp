#include "TLS.h"

#ifndef WOLFSSL_LOGGING
#define LOG(X)
#endif
#include <fstream>

extern "C" {
#include "wolfssl/error-ssl.h"
}

namespace osuCrypto
{

    namespace {
        error_code readFile(const std::string& file, std::vector<u8>& buffer)
        {
            std::ifstream t(file);

            if (t.is_open() == false)
                return boost::system::errc::make_error_code(boost::system::errc::no_such_file_or_directory);

            t.seekg(0, std::ios::end);
            buffer.resize(0);
            buffer.reserve(t.tellg());
            t.seekg(0, std::ios::beg);

            buffer.insert(buffer.end(), (std::istreambuf_iterator<char>(t)),
                std::istreambuf_iterator<char>());

            return {};
        }
    }

    std::mutex WolfInitMtx;

    WolfContext::Base::Base(bool isServer)
    {
        {
            std::lock_guard<std::mutex> lock(WolfInitMtx);
            if(isServer)
                mMethod = (wolfSSLv23_server_method());
            else
                mMethod = (wolfSSLv23_client_method());

            mCtx = (wolfSSL_CTX_new(mMethod));
        }
        wolfSSL_SetIOSend(mCtx, WolfSocket::sendCallback);
        wolfSSL_SetIORecv(mCtx, WolfSocket::recvCallback);
        mIsServer = isServer;

    }
    WolfContext::Base::~Base()
    {
        wolfSSL_CTX_free(mCtx);
    }


    void WolfContext::initServer(error_code& ec)
    {
        if (isInit())
        {
            ec = make_error_code(TLS_errc::ContextAlreadyInit);
            return;
        }
        mBase = std::make_shared<Base>(true);

        if (isInit() == false)
            ec = make_error_code(TLS_errc::ContextFailedToInit);
    }

    void WolfContext::initClient(error_code& ec)
    {
        if (isInit())
        {
            ec = make_error_code(TLS_errc::ContextAlreadyInit);
            return;
        }
        mBase = std::make_shared<Base>(false);

        if (isInit() == false)            
            ec = make_error_code(TLS_errc::ContextFailedToInit);
    }

    void WolfContext::loadCertFile(std::string path, error_code& ec)
    {
        if (isInit() == false)
            ec = make_error_code(TLS_errc::ContextNotInit);
        else
        {
            std::vector<unsigned char> data;
            ec = readFile(path, data);
            if (!ec) 
                loadCert(data, ec);
        }
    }

    void WolfContext::loadCert(span<u8> data, error_code& ec)
    {
        if (isInit() == false)
            ec = make_error_code(TLS_errc::ContextNotInit);
        else
            ec = wolfssl_error_code(
                wolfSSL_CTX_load_verify_buffer(*this, data.data(), data.size(), WOLFSSL_FILETYPE_PEM));
    }

    void WolfContext::loadKeyPairFile(std::string pkPath, std::string skPath, error_code& ec)
    {
        if (isInit() == false) {
            ec = make_error_code(TLS_errc::ContextNotInit);
            return;
        }
        
        std::vector<unsigned char> pk, sk;
        ec = readFile(pkPath, pk);
        if (ec) return;
        ec = readFile(skPath, sk);
        if (ec) return;

        loadKeyPair(pk, sk, ec);
    }

    void WolfContext::loadKeyPair(span<u8> pk, span<u8> sk, error_code& ec)
    {
        if (isInit() == false) {
            ec = make_error_code(TLS_errc::ContextNotInit);
            return;
        }

        ec = wolfssl_error_code(
            wolfSSL_CTX_use_certificate_buffer(*this, pk.data(), pk.size(), WOLFSSL_FILETYPE_PEM));
        if (ec) return;

        ec = wolfssl_error_code(
            wolfSSL_CTX_use_PrivateKey_buffer(*this, sk.data(), sk.size(), WOLFSSL_FILETYPE_PEM));
    }

    void WolfContext::requestClientCert(error_code& ec)
    {
        if (isInit() == false) 
            ec = make_error_code(TLS_errc::ContextNotInit);
        else  if (mBase->mIsServer == false) 
            ec = make_error_code(TLS_errc::OnlyValidForServerContext);
        else
        {
            wolfSSL_CTX_set_verify(*this, SSL_VERIFY_PEER, 0);
            ec = {};
        }
    }

    WolfSocket::WolfSocket(boost::asio::io_context& ios, WolfContext& ctx)
        : mSock(ios)
        , mStrand(ios.get_executor())
        , mIos(ios)
        , mSSL(wolfSSL_new(ctx))
        , mLog(mLog_)
    {
        if (mSSL)
        {
            wolfSSL_SetIOWriteCtx(mSSL, this);
            wolfSSL_SetIOReadCtx(mSSL, this);
        }
        else
        {
            throw std::runtime_error("Context not init correctly.");
        }
    }

    WolfSocket::WolfSocket(boost::asio::io_context& ios, boost::asio::ip::tcp::socket&& sock, WolfContext& ctx)
        : mSock(std::move(sock))
        , mStrand(ios.get_executor())
        , mIos(ios)
        , mSSL(wolfSSL_new(ctx))
        , mLog(mLog_)
    {
        wolfSSL_SetIOWriteCtx(mSSL, this);
        wolfSSL_SetIOReadCtx(mSSL, this);
    }



    void WolfSocket::close()
    {

        mSock.close();
        TODO("call wolf shutdown?");
    }

    void WolfSocket::send(
        span<buffer> buffers,
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

    void WolfSocket::async_send(
        span<buffer> buffers,
        io_completion_handle&& fn)
    {
#ifdef WOLFSSL_LOGGING
        std::stringstream ss;
        ss << "async_send ";
        for (auto b : buffers)
            ss << b.size() << " ";
        LOG(ss.str());
#endif

        assert(mSendBufs.size() == 0);

        assert(buffers.size());
        for (u64 i = 0; i < buffers.size(); ++i)
            assert(buffers[i].size());

        mSendCB = std::move(fn);
        mSendBufs.insert(mSendBufs.end(), buffers.begin(), buffers.end());
        mSendBufIdx = 0;

        sendNext();
    }

    void WolfSocket::sendNext()
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
                    mSendEC = wolfssl_error_code(err);
                    auto fn = mSendCB;
                    auto bt = mSendBT;
                    mSendBT = 0;
                    fn(mSendEC, bt);
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
                        auto fn = mSendCB;
                        auto bt = mSendBT;
                        mSendBT = 0;
                        fn(mSendEC, bt);
                    }
                }
                else
                {
                    LOG("redo send buffer");
                    curSendBuffer() = buffer(buf + ret, size - ret);
                    sendNext();
                }
            }

            });

    }

    int WolfSocket::sslRquestSendCB(char* buf, int size)
    {
        LOG("sslRquestSendCB " + std::string(mState.hasPendingRecv() ? "complete" : "init"));

        assert(mStrand.running_in_this_thread());

        if (mState.hasPendingSend() == false)
        {
            mState.mPendingSendBuf = { buf, size };
            buffer b(buf, size);
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

    void WolfSocket::recv(
        span<buffer> buffers,
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

    void WolfSocket::async_recv(
        span<buffer> buffers,
        io_completion_handle&& fn)
    {

#ifdef WOLFSSL_LOGGING
        std::stringstream ss;
        ss << "async_recv ";
        for (auto b : buffers)
            ss << b.size() << " ";
        LOG(ss.str());
#endif

        assert(mRecvBufs.size() == 0);
        assert(buffers.size());
        for (u64 i = 0; i < buffers.size(); ++i)
            assert(buffers[i].size());

        mRecvCB = std::move(fn);
        mRecvBufs.insert(mRecvBufs.end(), buffers.begin(), buffers.end());
        mRecvBufIdx = 0;

        recvNext();
    }

    void osuCrypto::WolfSocket::setDHParamFile(std::string path, error_code& ec)
    {
        std::vector<u8> paramData;
        if (!(ec = readFile(path, paramData)))
            setDHParam(paramData, ec);
    }

    void osuCrypto::WolfSocket::setDHParam(span<u8> data, error_code& ec)
    {
        ec = wolfssl_error_code(
            wolfSSL_SetTmpDH_buffer(mSSL, data.data(), data.size(), WOLFSSL_FILETYPE_PEM));
    }

    void WolfSocket::recvNext()
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
                    mRecvEC = wolfssl_error_code(err);
                    auto fn = std::move(mRecvCB);
                    auto bt = mRecvBT;
                    mRecvBT = 0;
                    fn(mRecvEC, bt);
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
                        auto fn = std::move(mRecvCB);
                        auto bt = mRecvBT;
                        mRecvBT = 0;
                        fn(mRecvEC, bt);
                    }
                }
                else
                {
                    // update the current buffer to point to what is left...
                    LOG("redo recv buffer");
                    curRecvBuffer() = buffer(buf + ret, size - ret);
                    recvNext();
                }
            }
            }
        );
    }

    int WolfSocket::sslRquestRecvCB(char* buf, int size)
    {
        LOG("sslRquestRecvCB " + std::string(mState.hasPendingRecv() ? "complete" : "init"));

        assert(mStrand.running_in_this_thread());

        if (mState.hasPendingRecv() == false)
        {
            mState.mPendingRecvBuf = { buf,  size };
            buffer b(buf, size);
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

    void WolfSocket::connect(error_code& ec)
    {
        std::promise<error_code> prom;
        async_connect([&prom](const error_code& ec) { prom.set_value(ec); });
        ec = prom.get_future().get();
    }

    void WolfSocket::async_connect(completion_handle&& cb)
    {
        LOG("async_connect");

        assert(mState.mPhase == WolfState::Phase::Uninit);
        mState.mPhase = WolfState::Phase::Connect;
        mSetupCB = std::move(cb);
        connectNext();
    }


    void WolfSocket::connectNext()
    {
        LOG("connectNext");
        boost::asio::dispatch(mStrand, [this]() {

            assert(mState.mPhase == WolfState::Phase::Connect);

            if (mCancelingPending)
            {
                auto fn = std::move(mSetupCB);
                fn(mSetupEC);
            }
            else
            {
                int ret, err = 0;
                ret = wolfSSL_connect(mSSL);
                if (ret != WOLFSSL_SUCCESS)
                    err = wolfSSL_get_error(mSSL, 0);

                if (ret == WOLFSSL_SUCCESS) {
                    mState.mPhase = WolfState::Phase::Normal;
                    auto fn = std::move(mSetupCB);
                    fn(mSetupEC);
                }
                else if (
                    err != WOLFSSL_ERROR_WANT_READ &&
                    err != WOLFSSL_ERROR_WANT_WRITE)
                {

                    if (mSendEC)
                    {
                        assert(err == SOCKET_ERROR_E);
                        mSetupEC = mSendEC;
                    }
                    else if (mRecvEC)
                    {
                        assert(err == SOCKET_ERROR_E);
                        mSetupEC = mRecvEC;
                    }
                    else
                    {
                        mSetupEC = wolfssl_error_code(err);

                        if (mState.hasPendingRecv() || mState.hasPendingSend())
                        {
                            // make sure they both aren't pending. No logic for this case.
                            assert(mState.hasPendingRecv() != mState.hasPendingSend());

                            mSock.close();
                            mCancelingPending = true;
                            return;
                        }
                    }
                    auto fn = std::move(mSetupCB);
                    fn(mSetupEC);
                }
            }
            }
        );
    }

    void WolfSocket::accept(error_code& ec)
    {
        std::promise<error_code> prom;
        async_accept([&prom](const error_code& ec) {
            prom.set_value(ec);
            }
        );
        ec = prom.get_future().get();
    }

    void WolfSocket::async_accept(completion_handle&& cb)
    {
        LOG("async_accept");
        assert(mState.mPhase == WolfState::Phase::Uninit);
        mState.mPhase = WolfState::Phase::Accept;
        mSetupCB = std::move(cb);
        acceptNext();
    }

    void WolfSocket::acceptNext()
    {
        LOG("acceptNext");
        boost::asio::dispatch(mStrand, [this]() {

            assert(mState.mPhase == WolfState::Phase::Accept);

            if (mCancelingPending)
            {
                auto fn = std::move(mSetupCB);
                fn(mSetupEC);
            }
            else
            {
                int ret, err = 0;
                ret = wolfSSL_accept(mSSL);
                if (ret != WOLFSSL_SUCCESS)
                    err = wolfSSL_get_error(mSSL, 0);

                if (ret == WOLFSSL_SUCCESS) {
                    mState.mPhase = WolfState::Phase::Normal;
                    auto fn = std::move(mSetupCB);
                    fn(mSetupEC);
                }
                else if (
                    err != WOLFSSL_ERROR_WANT_READ &&
                    err != WOLFSSL_ERROR_WANT_WRITE)
                {
                    if (mSendEC)
                    {
                        assert(err == SOCKET_ERROR_E);
                        mSetupEC = mSendEC;
                    }
                    else if (mRecvEC)
                    {
                        assert(err == SOCKET_ERROR_E);
                        mSetupEC = mRecvEC;
                    }
                    else
                    {
                        mSetupEC = wolfssl_error_code(err);
                        if (mState.hasPendingRecv() || mState.hasPendingSend())
                        {
                            // make sure they both aren't pending. No logic for this case.
                            assert(mState.hasPendingRecv() != mState.hasPendingSend());

                            mSock.close();
                            mCancelingPending = true;
                            return;
                        }
                    }
                    auto fn = std::move(mSetupCB);
                    fn(mSetupEC);
                }
            }
            }
        );
    }
#ifdef WOLFSSL_LOGGING
    void WolfSocket::LOG(std::string X) {
#ifdef WOLFSSL_LOGGING_VERBODSE
        if (wolfSSL_is_server(mSSL) == false)
            lout << Color::Red << "client " << (X) << std::endl << Color::Default;
        else
            lout << Color::Green << "server " << (X) << std::endl << Color::Default;
#endif
        mLog.push(X);
    }
#endif

}