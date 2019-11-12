#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/IOService.h>
#include <thread>
#include <chrono>

namespace osuCrypto {



#ifdef ENABLE_NET_LOG
#define LOG_MSG(m) mLog.push(m);
#define IF_LOG(m) m

#else
#define LOG_MSG(m)
#define IF_LOG(m) 
#endif

    auto startTime = std::chrono::system_clock::time_point::clock::now();

    std::string time()
    {
        std::stringstream ss;
        auto now = std::chrono::system_clock::time_point::clock::now();
        auto time = std::chrono::duration_cast<std::chrono::microseconds>(now - startTime).count() / 1000.0;

        ss << time << "ms";
        return ss.str();
    }

    Channel::Channel(
        Session& endpoint,
        std::string localName,
        std::string remoteName)
        :
        mBase(new ChannelBase(endpoint, localName, remoteName))
    {
        mBase->mStartOp = std::make_unique<StartSocketOp>(mBase);

        //if (mBase->mSession->mMode == SessionMode::Server)
        //    mBase->mSession->mAcceptor->subscribe(mBase);

        if (mBase->mSession->mMode == SessionMode::Server)
        {
            IF_LOG(mBase->mLog.push("calling Acceptor::asynGetSocket(...) "));

            mBase->mSession->mAcceptor->asyncGetSocket(mBase);
        }
        else
        {
            IF_LOG(mBase->mLog.push("calling asyncConnectToServer(...) "));
            mBase->mStartOp->asyncConnectToServer();
        }
        // StartSocketRecvOp  ss(mBase->mStartOp.get());
        // details::RecvOperation& vv = ss;

        mBase->recvEnque(make_SBO_ptr<details::RecvOperation, StartSocketRecvOp>(mBase->mStartOp.get()));
        mBase->sendEnque(make_SBO_ptr<details::SendOperation, StartSocketSendOp>(mBase->mStartOp.get()));

    }

    Channel::Channel(IOService& ios, SocketInterface* sock)
        : mBase(new ChannelBase(ios, sock))
    {}


    ChannelBase::ChannelBase(
        Session& endpoint,
        std::string localName,
        std::string remoteName)
        :
        mIos(endpoint.getIOService()),
        mWork(new boost::asio::io_service::work(endpoint.getIOService().mIoService)),
        mSession(endpoint.mBase),
        mRemoteName(remoteName),
        mLocalName(localName),
        mChannelRefCount(1),
        mSendStrand(endpoint.getIOService().mIoService.get_executor()),
        mRecvStrand(endpoint.getIOService().mIoService.get_executor())
    {
    }

    ChannelBase::ChannelBase(IOService& ios, SocketInterface* sock)
        :
        mIos(ios),
        mWork(new boost::asio::io_service::work(ios.mIoService)),
        mChannelRefCount(1),
        mHandle(sock),
        mSendStrand(ios.mIoService.get_executor()),
        mRecvStrand(ios.mIoService.get_executor())
    {
    }

    ChannelBase::~ChannelBase()
    {
        assert(mChannelRefCount ==0);
    }


    StartSocketOp::StartSocketOp(std::shared_ptr<ChannelBase> chl) :
        mTimer(chl->mIos.mIoService),
        mStrand(chl->mIos.mIoService.get_executor()),
        mSock(nullptr),
        mChl(chl.get())
    {}


    void StartSocketOp::asyncPerform(ChannelBase* base, io_completion_handle&& completionHandle, bool sendOp)
    {
        IF_LOG(mChl->mLog.push(
            "calling StartSocketOp::asyncPerform(...) send="
            + std::to_string(sendOp)));

        if (sendOp)
            mSendComHandle = completionHandle;
        else
            mRecvComHandle = completionHandle;

        boost::asio::post(mStrand, [this, sendOp]() {

            if (sendOp)
                mSendStatus = ComHandleStatus::Init;
            else
                mRecvStatus = ComHandleStatus::Init;

            if (mSendStatus == ComHandleStatus::Init && mIsComplete)
            {
                mSendStatus = ComHandleStatus::Eval;
                mSendComHandle(mEC, 0);
            }

            if (mRecvStatus == ComHandleStatus::Init && mIsComplete)
            {
                mRecvStatus = ComHandleStatus::Eval;
                mRecvComHandle(mEC, 0);
            }
            }
        );
    }

    void StartSocketOp::cancel()
    {
        IF_LOG(mChl->mLog.push("calling StartSocketOp::cancel(...) " + time()));
        //lout << "calling StartSocketOp::cancel(...) " << time() << std::endl;
        auto lifetime = mChl->shared_from_this();
        boost::asio::post(mStrand, [this, lifetime]() {

            if (mIsComplete == false && canceled() == false)
            {
                IF_LOG(mChl->mLog.push("in StartSocketOp::cancel(...) " + time()));

                mCanceled = true;

#ifdef ENABLE_WOLFSSL
                if (mTLSSock)
                {
                    mTLSSock->close();
                    //auto ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
                    //finalize(std::move(mTLSSock), ec);
                }
                else 
#endif
                if (mChl->mSession->mAcceptor)
                {
                    mChl->mSession->mAcceptor->cancelPendingChannel(mChl->shared_from_this());
                }
                else  if (mSock)
                {
                    error_code ec;
                    mSock->mSock.close(ec);
                }
            }
            
            }
        );
    }

    void StartSocketOp::setSocket(std::unique_ptr<BoostSocketInterface> socket, const error_code& ec)
    {
        //lout << "calling StartSocketOp::setSocket(...) " << time() << std::endl;
        IF_LOG(mChl->mLog.push("Recved socket, starting up the queues..."));

        boost::asio::post(mStrand, [this, ec, s = std::move(socket)]() mutable {

            if (canceled() && s)
            {
                if (mChl->mSession->mMode == SessionMode::Client)
                {
                    s->close();
                }
                else
                {
                    // At the same time that we called cancel(), the
                    // Acceptor made this call to setSocket(...). 
                    // Let us ignore this one and wait for the next call
                    // to setSocket() that Acceptor::cancelPendingChannel(...)
                    // is going to make.
                    return;
                }
            }

#ifdef ENABLE_WOLFSSL
            if (mChl->mSession->mTLSContext && !ec)
            {
                mTLSSock.reset(new TLSSocket(mChl->mIos.mIoService, std::move(s->mSock), mChl->mSession->mTLSContext));
                
                IF_LOG(mTLSSock->setLog(mChl->mLog));

                if (mChl->mSession->mMode == SessionMode::Client)
                {
                    IF_LOG(mChl->mLog.push("tls async_connect()"));
                    mTLSSock->async_connect([this](const error_code& ec) 
                    {
                            IF_LOG(mChl->mLog.push("tls async_connect() done, " + ec.message()));
                        finalize(std::move(mTLSSock), ec);
                        });
                }
                else
                {
                    IF_LOG(mChl->mLog.push("tls async_accept() " + ec.message()));
                    mTLSSock->async_accept([this](const error_code& ec) {
                        IF_LOG(mChl->mLog.push("tls async_accept() done, " + ec.message()));
                        finalize(std::move(mTLSSock), ec);
                        });
                }
                //mChl->mSession->mTLSContext.
            }
            else
#endif
            {
                finalize(std::move(s), ec);
            }

        }
        );
    }

    void StartSocketOp::finalize(std::unique_ptr<SocketInterface> sock, error_code ec)
    {
        boost::asio::dispatch(mStrand, [this, s = std::move(sock), ec]() mutable {
            assert(mIsComplete == false);

            mChl->mHandle = std::move(s);
            mEC = ec;

            mIsComplete = true;
            while (mComHandles.size())
            {
                boost::asio::post(mChl->mIos.mIoService.get_executor(),
                    [fn = std::move(mComHandles.front()), ec = mEC](){fn(ec); });
                mComHandles.pop_front();
            }

            if (mSendStatus == ComHandleStatus::Init)
            {
                mSendStatus = ComHandleStatus::Eval;
                mSendComHandle(mEC, 0);
            }

            if (mRecvStatus == ComHandleStatus::Init)
            {
                mRecvStatus = ComHandleStatus::Eval;
                mRecvComHandle(mEC, 0);
            }
            }
        );
    }

    bool StartSocketOp::canceled() const { return mCanceled; }

    void StartSocketOp::asyncConnectToServer()
    {
        //lout << "calling StartSocketOp::asyncConnectToServer(...) " << time() << std::endl;

        auto& address = mChl->mSession->mRemoteAddr;

        IF_LOG(mChl->mLog.push("start async connect to server at " +
            address.address().to_string() + " : " + std::to_string(address.port())));

        mSock.reset(new BoostSocketInterface(
            boost::asio::ip::tcp::socket(mChl->getIOService().mIoService)));

        //mSock = &ptr->mSock;
        //mChl->mHandle.reset(ptr);

        mConnectCallback = [this](const boost::system::error_code& ec)
        {
            IF_LOG(mChl->mLog.push("calling StartSocketOp::asyncConnectToServer(...) cb1 "));

            boost::asio::dispatch(mStrand, [this, ec] {
                // lout << "calling StartSocketOp::asyncConnectToServer(...) cb1 " << time() << std::endl;

                IF_LOG(mChl->mLog.push("in StartSocketOp::asyncConnectToServer(...) cb1 "
                    + ec.message()));

                auto& sock = mSock->mSock;

                if (canceled() || ec == boost::system::errc::operation_canceled)
                {
                    auto ec2 = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
                    setSocket(nullptr, ec2);
                }
                else if (ec)
                {

                    retryConnect(ec);
                }
                else
                {
                    boost::asio::ip::tcp::no_delay option(true);
                    error_code ec2;
                    sock.set_option(option, ec2);

                    if (ec2)
                    {
                        auto msg = "async connect. Failed to set option ~ ec=" + ec2.message() + "\n"
                            + " isOpen=" + std::to_string(sock.is_open())
                            + " stopped=" + std::to_string(canceled());

                        IF_LOG(mChl->mLog.push(msg));

                        // retry.
                        retryConnect(ec2);
                    }
                    else
                    {
                        recvServerMessage();
                    }
                }
                }
            );
        };


        mSock->mSock.async_connect(address, mConnectCallback);
    }

    void StartSocketOp::recvServerMessage()
    {
        auto buffer = boost::asio::buffer((char*)&mRecvChar, 1);
        auto& sock = mSock->mSock;

        sock.async_receive(buffer, [this](const error_code& ec, u64 bytesTransferred) {
            boost::asio::dispatch(mStrand, [this, ec, bytesTransferred] {

                if (canceled())
                {
                    auto ec2 = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
                    setSocket(nullptr, ec2);
                }
                else if (ec || bytesTransferred != 1)
                {
                    retryConnect(ec);
                }
                else if (mRecvChar != 'q')
                {
                    auto ec2 = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
                    setSocket(nullptr, ec2);
                }
                else
                {
                    sendConnectionString();
                }
                }
            );
            }
        );
    }

    void StartSocketOp::sendConnectionString()
    {

        std::stringstream sss;
        sss << mChl->mSession->mName << '`'
            << mChl->mSession->mSessionID << '`'
            << mChl->mLocalName << '`'
            << mChl->mRemoteName;

        auto str = sss.str();
        mSendBuffer.resize(sizeof(details::size_header_type) + str.size());
        *(details::size_header_type*)mSendBuffer.data()
            = static_cast<details::size_header_type>(str.size());

        std::copy(str.begin(), str.end(), mSendBuffer.begin() + sizeof(details::size_header_type));


        IF_LOG(mChl->mLog.push("Success: async connect to server. ConnectionString = " \
            + str + " " + std::to_string((u64) & *mChl->mHandle)));

        auto buffer = boost::asio::buffer((char*)mSendBuffer.data(), mSendBuffer.size());
        auto& sock = mSock->mSock;;

        sock.async_send(buffer, [this](const error_code& ec, u64 bytesTransferred) {
            boost::asio::dispatch(mStrand, [this, ec, bytesTransferred] {

                if (canceled())
                {
                    auto ec2 = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
                    setSocket(nullptr, ec2);
                }
                else if (ec || bytesTransferred != mSendBuffer.size())
                {
                    auto& sock = mSock->mSock;

                    auto msg = "async connect. Failed to send ConnectionString ~ ec=" + ec.message() + "\n"
                        + " isOpen=" + std::to_string(sock.is_open())
                        + " canceled=" + std::to_string(canceled());

                    IF_LOG(mChl->mLog.push(msg));

                    // Unknown issue where we connect but then the pipe is broken. 
                    // Simply retrying seems to be a workaround.
                    retryConnect(ec);
                }
                else
                {
                    IF_LOG(mChl->mLog.push("async connect. ConnectionString sent."));
                    setSocket(std::move(mSock), ec);
                }
                }
            );
            }
        );
    }

    void osuCrypto::StartSocketOp::retryConnect(const error_code& ec)
    {


        error_code ec2;
        mSock->mSock.close(ec2);

        IF_LOG(if (ec2)
            mChl->mLog.push("error closing boost socket (3), ec = " + ec2.message()));

        auto count = static_cast<u64>(mBackoff);
        mTimer.expires_from_now(boost::posix_time::millisec(count));


        mBackoff = std::min(mBackoff * 1.2, 1000.0);
        if (mBackoff >= 1000.0)
        {
            switch (ec.value())
            {
            case boost::system::errc::operation_canceled:
            case boost::system::errc::connection_refused:
                break;
            default:
                mChl->mIos.printError("client socket connect error: " + ec.message());
            }

        }
        IF_LOG(mChl->mLog.push("retry async connect to server (delay " + std::to_string(count) + "ms), ec = " + ec.message()));


        mTimer.async_wait([this](const boost::system::error_code& ec) {
            if (ec)
            {
                setSocket(nullptr, ec);
            }
            else
            {

                auto& address = mChl->mSession->mRemoteAddr;
                mSock->mSock.async_connect(address, mConnectCallback);
            }
            }
        );
    }





    std::string Channel::getName() const
    {
        return mBase->mLocalName;
    }

    Channel& Channel::operator=(Channel&& move)
    {
        if(mBase) 
            --mBase->mChannelRefCount;
        mBase = std::move(move.mBase);
        return *this;
    }

    Channel& Channel::operator=(const Channel& copy)
    {
        if(mBase) 
            --mBase->mChannelRefCount;
        mBase = copy.mBase;
        if(mBase)
            ++mBase->mChannelRefCount;
        return *this;
    }

    Channel::Channel(const Channel& copy)
        :mBase(copy.mBase)
    {
        if(mBase)
            mBase->mChannelRefCount++;
    }

    Channel::~Channel()
    {
        if(mBase && --mBase->mChannelRefCount == 0)
            mBase->close();
    }

    bool Channel::isConnected()
    {
        if (mBase->mStartOp)
            return mBase->mStartOp->mIsComplete && !mBase->mStartOp->mEC;

        return true;
    }

    bool Channel::waitForConnection(std::chrono::milliseconds timeout)
    {
        if (mBase->mStartOp)
        {
            auto prom = std::make_shared<std::promise<void>>();
            mBase->mStartOp->addComHandle([prom](const error_code& ec) {
                //lout << "is complete " << mBase->mStartOp->mIsComplete << std::endl;
                if (ec)
                    prom->set_exception(std::make_exception_ptr(SocketConnectError("failed to connect. ")));
                else
                    prom->set_value();
                });

            auto fut = prom->get_future();

            //auto deadline = std::chrono::high_resolution_clock::now() + timeout;

            auto status = fut.wait_for(timeout);
            if (status != std::future_status::timeout ||
                timeout == std::chrono::hours::max())
            {
                //if (status == std::future_status::deferred)
                //    lout << "odd ........." << std::endl;
                //else
                //    lout << "status == ready" << std::endl;

                fut.get(); // may throw...
                return true;
            }
            else
            {
                //lout << "status == timeout" << std::endl;
                return false;
            }
        }
        return true;
    }

    void Channel::waitForConnection()
    {
        waitForConnection(std::chrono::hours::max());
    }

    void Channel::onConnect(completion_handle handle)
    {
        if (mBase->mStartOp)
        {
            mBase->mStartOp->addComHandle(std::move(handle));
        }
        else
        {
            auto ec = boost::system::errc::make_error_code(boost::system::errc::success);
            handle(ec);
        }
    }

    void Channel::close()
    {
        if (mBase) mBase->close();
    }

    void Channel::cancel()
    {
        if (mBase) mBase->cancel();
    }

    void Channel::asyncClose(std::function<void()> completionHandle)
    {
        if (mBase) mBase->asyncClose(std::move(completionHandle));
        else completionHandle();
    }

    void Channel::asyncCancel(std::function<void()> completionHandle)
    {
        if (mBase) mBase->asyncCancel(std::move(completionHandle));
        else completionHandle();
    }

    std::string osuCrypto::Channel::commonName()
    {
        if(mBase)
            return mBase->commonName();
        return {};
    }

    std::string ChannelBase::commonName()
    {
#ifdef ENABLE_WOLFSSL
        auto tls = dynamic_cast<TLSSocket*>(mHandle.get());
        if (tls)
            return tls->getCert().commonName();
#endif
        return {};
    }

    void ChannelBase::recvEnque(SBO_ptr<details::RecvOperation>&& op)
    {
#ifdef ENABLE_NET_LOG
        op->mIdx = mRecvIdx++;
#endif
        auto str = op->toString();
        LOG_MSG("recv queuing op " + str);

        auto& movedOp = mRecvQueue.push_back(std::move(op));
        
#ifdef ENABLE_NET_LOG
        assert(movedOp->mIdx == mRecvIdx - 1);
#endif
        // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
        boost::asio::dispatch(mRecvStrand, [this, str]()
            {


                // check to see if we should kick off a new set of recv operations. If the size >= 1, then there
                // is already a set of recv operations that will kick off the newly queued recv when its turn comes around.
                bool hasItems = (mRecvQueue.isEmpty() == false);
                bool available = recvSocketAvailable();
                bool startRecving = hasItems && available;

                LOG_MSG("recv queuing "+str+": start = " + std::to_string(startRecving) + " = " + std::to_string(hasItems) + " && " + std::to_string(available));
                // the queue must be guarded from concurrent access, so add the op within the strand
                // queue up the operation.
                if (startRecving)
                {
                    // ok, so there isn't any recv operations currently underway. Lets kick off the first one. Subsequent recvs
                    // will be kicked off at the completion of this operation.
                    mRecvLoopLifetime = shared_from_this();
                    asyncPerformRecv();
                }
            });
    }

    void ChannelBase::sendEnque(SBO_ptr<details::SendOperation>&& op)
    {

#ifdef ENABLE_NET_LOG
        op->mIdx = mSendIdx++;
#endif
        auto str = op->toString();
        LOG_MSG("send queuing op " + str);

        mSendQueue.push_back(std::move(op));

        // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
        boost::asio::dispatch(mSendStrand, [this, str]()
            {
                auto hasItems = (mSendQueue.isEmpty() == false);
                auto avaliable = sendSocketAvailable();
                auto startSending = hasItems && avaliable;

                LOG_MSG("send queuing "+str+": start = " + std::to_string(startSending) + " = " + std::to_string(hasItems)
                    + " & " + std::to_string(avaliable));

                if (startSending)
                {
                    mSendLoopLifetime = shared_from_this();
                    asyncPerformSend();
                }
            });
    }


    void ChannelBase::asyncPerformRecv()
    {
        LOG_MSG("recv start: " + mRecvQueue.front()->toString());
        assert(mRecvStrand.running_in_this_thread());

#ifdef ENABLE_NET_LOG
        mRecvQueue.front()->mLog = &mLog;
#endif

        if (mRecvCancelNew == false)
        {
            mRecvQueue.front()->asyncPerform(this, [this](error_code ec, u64 bytesTransferred) {

                mTotalRecvData += bytesTransferred;

                boost::asio::dispatch(mRecvStrand, [this, ec]() {
                    if (!ec)
                    {
                        LOG_MSG("recv completed: " + mRecvQueue.front()->toString());

                        mRecvQueue.pop_front();

                        LOG_MSG("recv pop from main");  
                        if (!mRecvQueue.isEmpty())
                            asyncPerformRecv();
                        else
                            mRecvLoopLifetime = nullptr;
                    }
                    else
                    {
                        LOG_MSG("recv pop from main error");  
                        mRecvQueue.pop_front();
                        auto reason = std::string("network receive error (") +
                            mSession->mName + " " + mRemoteName + " -> " + mLocalName + " ): "
                            + ec.message() + "\n at  " + LOCATION;

                        LOG_MSG(reason);

                        if (mIos.mPrint)
                            lout << reason << std::endl;

                        cancelRecvQueue(ec);
                    }
                    });

                }
            );
        }
        else
        {
            auto ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
            cancelRecvQueue(ec);
        }
    }

    void ChannelBase::asyncPerformSend()
    {
        LOG_MSG("send start: " + mSendQueue.front()->toString());

        assert(mSendStrand.running_in_this_thread());
    
#ifdef ENABLE_NET_LOG
        mSendQueue.front()->mLog = &mLog;
#endif

        if (mSendCancelNew == false)
        {

            mSendQueue.front()->asyncPerform(this, [this](error_code ec, u64 bytesTransferred) {

                mTotalSentData += bytesTransferred;

                boost::asio::dispatch(mSendStrand, [this, ec]() {
                    if (!ec)
                    {
                        LOG_MSG("send completed: " + mSendQueue.front()->toString());

                        mSendQueue.pop_front();

                        if (!mSendQueue.isEmpty())
                        {
                            //LOG_MSG("has more sends ...");
                            asyncPerformSend();
                        }
                        else
                            mSendLoopLifetime = nullptr;
                    }
                    else
                    {
                        auto reason = std::string("network send error: ") + ec.message() + "\n at  " + LOCATION;
                        LOG_MSG(reason);
                         
                        mSendQueue.pop_front();

                        if (mIos.mPrint)
                            lout << reason << std::endl;

                        cancelSendQueue(ec);
                    }
                    });
                });
        }
        else
        {
            auto ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
            cancelSendQueue(ec);
        }
        
    }

    void ChannelBase::printError(std::string s)
    {
        LOG_MSG(s);
        mIos.printError(s);
    }



    void ChannelBase::cancel()
    {
        std::promise<void> prom;
        asyncCancel([&]() {

            prom.set_value();
            //lout << "cancel(...) done " << time() << std::endl;
            });

        prom.get_future().get();
    }

    void ChannelBase::asyncCancel(std::function<void()> completionHandle)
    {
        LOG_MSG("cancel()");

        if (stopped() == false)
        {
            mStatus = Channel::Status::Canceling;
            auto ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
            // mRecvCancelNew = true;
            // mSendCancelNew = true;

            auto count = std::make_shared<std::atomic<u32>>(2);
            auto cb = [&, ch = std::move(completionHandle), count]() mutable{
                if(--*count == 0)
                {
                    mHandle.reset(nullptr);
                    mWork.reset(nullptr);

                    LOG_MSG("cancel callback.");

                    auto c = std::move(ch);
                    c();
                }
            };

            if (mHandle)
            {
                mHandle->close();
            }

            auto lifetime = shared_from_this();

            //details::SendCallbackOp ss(cb);

            // cancel the front item. Closing the socket will likely
            // also cancel the front item but in case not we give the
            // operation another chance to be cancel.
            boost::asio::dispatch(mSendStrand, [this, lifetime, ec, cb]() mutable{
                sendEnque(make_SBO_ptr<details::SendOperation, details::SendCallbackOp>(std::move(cb)));
                if (mSendQueue.isEmpty() == false && sendSocketAvailable() == false)
                {
                    LOG_MSG("cancel send asyncCancelPending(...).");
                    mSendQueue.front()->asyncCancelPending(this, ec);
                }
                else
                {
                    LOG_MSG("cancel cancelSendQueue(...).");
                    cancelSendQueue(ec);
                }
                });
            boost::asio::dispatch(mRecvStrand, [this, lifetime, ec, cb]() mutable {
                recvEnque(make_SBO_ptr<details::RecvOperation, details::RecvCallbackOp>(std::move(cb)));
                if (mRecvQueue.isEmpty() == false && recvSocketAvailable() == false)
                {
                    LOG_MSG("cancel recv asyncCancelPending(...).");
                    mRecvQueue.front()->asyncCancelPending(this, ec);
                }
                else
                {
                    LOG_MSG("cancel cancelRecvQueue(...).");
                    cancelRecvQueue(ec);
                }
                });
        }
        else
        {

            if (mStatus == Channel::Status::Closing ||
                mStatus == Channel::Status::Canceling)
            {
                lout << "Warning, asyncCancel() called on a canceling or closing channel " << mSession->mName << " " << mLocalName << std::endl;
            }
            completionHandle();
        }
    }

    void ChannelBase::close()
    {
        std::promise<void> prom;
        asyncClose([&]() { prom.set_value(); });
        prom.get_future().get();
    }

    void ChannelBase::asyncClose(std::function<void()> completionHandle)
    {
        LOG_MSG("Closing...");

        if (stopped() == false)
        {
            mStatus = Channel::Status::Closing;

            auto count = std::make_shared<std::atomic<u32>>(2);
            auto cb = [&, ch = std::move(completionHandle), count]() mutable {

                if(--*count == 0)
                {
                    mStatus = Channel::Status::Closed;

                    if (mHandle)
                    {
                        mHandle->close();
                    }
                    mHandle.reset(nullptr);
                    mWork.reset(nullptr);
                    LOG_MSG("Closed");

                    auto c = std::move(ch);
                    c();
                }
            };


            sendEnque(make_SBO_ptr<details::SendOperation, details::SendCallbackOp>(cb));
            recvEnque(make_SBO_ptr<details::RecvOperation, details::RecvCallbackOp>(cb));
     
        }
        else
        {
            if (mStatus == Channel::Status::Closing ||
                mStatus == Channel::Status::Canceling)
            {
                lout << "Warning, asyncClose() called on a canceling or closing channel." << std::endl;
            }
            completionHandle();
        }
    }




    void ChannelBase::cancelSendQueue(const error_code& ec)
    {
        //if (mSendStrand.running_in_this_thread() == false)
        //    throw RTE_LOC;

        //mStatus = Channel::Status::Canceling;
        mSendCancelNew = true;

        if (!mSendQueue.isEmpty())
        {
            auto& front = mSendQueue.front();
            front->asyncCancel(this, ec,[this, ec](const error_code& ec2, u64 bt) {

                boost::asio::dispatch(mSendStrand, [this, ec]() {
                    auto& front = mSendQueue.front();
                    LOG_MSG("send cancel op: " + std::to_string(front->mIdx));
                    mSendQueue.pop_front();

       
                    cancelSendQueue(ec);

                    });
                });
        }
        else
        {
            LOG_MSG("send queue empty");
            mSendLoopLifetime = nullptr;
        }
    }


    void ChannelBase::cancelRecvQueue(const error_code& ec)
    {
        //if (mRecvStrand.running_in_this_thread() == false)
        //    throw RTE_LOC;

        //mStatus = Channel::Status::Canceling;
        mRecvCancelNew = true;

        if (!mRecvQueue.isEmpty())
        {
            auto& front = mRecvQueue.front();
            LOG_MSG("recv cancel op: " + front->toString());

            front->asyncCancel(this, ec, [this, ec](const error_code& ec2, u64 bt) {
                boost::asio::dispatch(mRecvStrand, [ec, this]() {


                    LOG_MSG("recv pop from cancel queue");
                    mRecvQueue.pop_front();

                    cancelRecvQueue(ec);
                    });
                });
        }
        else
        {
            LOG_MSG("recv queue empty");
            mRecvLoopLifetime = nullptr;
        }
    }


    std::string Channel::getRemoteName() const
    {
        return mBase->mRemoteName;
    }

    Session Channel::getSession() const
    {
        if (mBase->mSession)
            return mBase->mSession;
        else
            throw std::runtime_error("no session. " LOCATION);
    }


    void Channel::resetStats()
    {
        mBase->mTotalSentData = 0;
        mBase->mTotalRecvData = 0;
    }

    u64 Channel::getTotalDataSent() const
    {
        std::promise<u64> prom;
        boost::asio::dispatch(mBase->mSendStrand, [&]() {
            prom.set_value(mBase->mTotalSentData);
            }
        );
        return prom.get_future().get();
    }

    u64 Channel::getTotalDataRecv() const
    {
        std::promise<u64> prom;
        boost::asio::dispatch(mBase->mRecvStrand, [&]() {
            prom.set_value(mBase->mTotalRecvData);
            }
        );
        return prom.get_future().get();
    }


}
