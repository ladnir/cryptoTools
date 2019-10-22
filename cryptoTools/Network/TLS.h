#pragma once
#include <string>
#include <boost/system/error_code.hpp>
#include <boost/asio/strand.hpp>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Common/Log.h>
#include <memory>

extern "C" {
#include <wolfssl/ssl.h>
//#include <wolfssl/test.h>
//#include <wolfssl/wolfcrypt/settings.h>
//#include <../wolfssl/IDE/WIN10/user_settings.h>
}
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#ifdef ENABLE_NET_LOG
#define WOLFSSL_LOGGING
#endif

namespace osuCrypto
{
    using error_code = boost::system::error_code;

    enum class WolfSSL_errc
    {
        Success = 0,
        Failure = 1
    };
    enum class TLS_errc
    {
        Success = 0,
        Failure,
        ContextNotInit,
        ContextAlreadyInit,
        ContextFailedToInit,
        OnlyValidForServerContext
    };
}

namespace boost {
    namespace system {
        template <>
        struct is_error_code_enum<osuCrypto::WolfSSL_errc> : true_type {};
        template <>
        struct is_error_code_enum<osuCrypto::TLS_errc> : true_type {};
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
            if (err == 0) return "Success";
            if (err == 1) return "Failure";
            return wolfSSL_ERR_error_string(err, buffer.data());
        }
    };

    const WolfSSLErrCategory WolfSSLCategory{};


    struct TLSErrCategory : boost::system::error_category
    {
        const char* name() const noexcept override
        {
            return "osuCrypto_TLS";
        }

        std::string message(int err) const override
        {
            switch (static_cast<osuCrypto::TLS_errc>(err))
            {
            case osuCrypto::TLS_errc::Success:
                return "Success";
            case osuCrypto::TLS_errc::Failure:
                return "Generic Failure";
            case osuCrypto::TLS_errc::ContextNotInit:
                return "TLS context not init";
            case osuCrypto::TLS_errc::ContextAlreadyInit:
                return "TLS context is already init";
            case osuCrypto::TLS_errc::ContextFailedToInit:
                return "TLS context failed to init";
            case osuCrypto::TLS_errc::OnlyValidForServerContext:
                return "Operation is only valid for server initialized TLC context";

            default:
                return "unknown error";
            }
        }
    };

    const TLSErrCategory TLSCategory{};

} // anonymous namespace

namespace osuCrypto
{
    inline error_code make_error_code(WolfSSL_errc e)
    {
        auto ee = static_cast<int>(e);
        return { ee, WolfSSLCategory };
    }

    inline error_code make_error_code(TLS_errc e)
    {
        auto ee = static_cast<int>(e);
        return { ee, TLSCategory };
    }


    inline error_code wolfssl_error_code(int ret)
    {
        switch (ret)
        {
        case WOLFSSL_SUCCESS: return make_error_code(WolfSSL_errc::Success);
        case WOLFSSL_FAILURE: return make_error_code(WolfSSL_errc::Failure);
        default: return make_error_code(WolfSSL_errc(ret));
        }
    }

    struct WolfContext
    {
        struct Base
        {
            WOLFSSL_METHOD* mMethod = nullptr;
            WOLFSSL_CTX* mCtx = nullptr;
            bool mIsServer = false;

            Base(bool isServer);
            ~Base();
        };

        std::shared_ptr<Base> mBase;



        void initServer(error_code& ec);
        void initClient(error_code& ec);

        void loadCertFile(std::string path, error_code& ec);
        void loadCert(span<u8> data, error_code& ec);

        void loadKeyPairFile(std::string pkPath, std::string skPath, error_code& ec);
        void loadKeyPair(span<u8> pkData, span<u8> skData, error_code& ec);

        void requestClientCert(error_code& ec);


        bool isInit() const {
            return mBase != nullptr;                
        }
        bool isServer() const {
            if (isInit())
                return mBase->mIsServer;
            else false;
        }

        operator bool() const
        {
            return isInit();
        }


        operator WOLFSSL_CTX* () const
        {
            return mBase ? mBase->mCtx : nullptr;
        }

    };

    using TLSContext = WolfContext;

    struct WolfSocket : public SocketInterface, public LogAdapter
    {

        using buffer = boost::asio::mutable_buffer;

        boost::asio::ip::tcp::socket mSock;
        boost::asio::strand<boost::asio::io_context::executor_type> mStrand;
        boost::asio::io_context& mIos;
        WOLFSSL* mSSL = nullptr;
#ifdef WOLFSSL_LOGGING
        oc::Log mLog_;
        oc::LogAdapter mLog;
#endif
        std::vector<buffer> mSendBufs, mRecvBufs;
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

        io_completion_handle mSendCB, mRecvCB;
        completion_handle mSetupCB, mShutdownCB;

        bool mCancelingPending = false;

        WolfSocket(boost::asio::io_context& ios, WolfContext& ctx);
        WolfSocket(boost::asio::io_context& ios, boost::asio::ip::tcp::socket&& sock, WolfContext& ctx);

        WolfSocket(WolfSocket&&) = delete;
        WolfSocket(const WolfSocket&) = delete;

        ~WolfSocket()
        {
            close();
            if (mSSL) wolfSSL_free(mSSL);
        }

        void close() override;

        void async_send(
            span<buffer> buffers,
            io_completion_handle&& fn) override;

        void async_recv(
            span<buffer> buffers,
            io_completion_handle&& fn) override;

        void setDHParamFile(std::string path, error_code& ec);
        void setDHParam(span<u8> paramData, error_code& ec);


        bool hasRecvBuffer() { return mRecvBufIdx < mRecvBufs.size(); }
        buffer& curRecvBuffer() { return mRecvBufs[mRecvBufIdx]; }

        bool hasSendBuffer() { return mSendBufIdx < mSendBufs.size(); }
        buffer& curSendBuffer() { return mSendBufs[mSendBufIdx]; }

        void send(
            span<buffer> buffers,
            error_code& ec,
            u64& bt);

        void sendNext();

        int sslRquestSendCB(char* buf, int size);

        void recv(
            span<buffer> buffers,
            error_code& ec,
            u64& bt);
        

        void recvNext();

        int sslRquestRecvCB(char* buf, int size);


        void connect(error_code& ec);
        void async_connect(completion_handle&& cb);
        void connectNext();

        void accept(error_code& ec);
        void async_accept(completion_handle&& cb);
        void acceptNext();

#ifdef WOLFSSL_LOGGING
        void LOG(std::string X);
#endif

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

    using TLSSocket = WolfSocket;



}