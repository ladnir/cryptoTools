#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/IOService.h>
namespace osuCrypto {

    Channel::Channel(
        Session& endpoint,
        std::string localName,
        std::string remoteName)
        :
        mBase(new ChannelBase(endpoint, localName, remoteName))
    {}

    Channel::Channel(IOService& ios, SocketInterface * sock)
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
        mRecvStatus(Channel::Status::Normal),
        mSendStatus(Channel::Status::Normal),
        mHandle(nullptr),
        mTimer(endpoint.getIOService().mIoService),
        mSendStrand(endpoint.getIOService().mIoService),
        mRecvStrand(endpoint.getIOService().mIoService),
        mOpenProm(),
        mOpenFut(mOpenProm.get_future()),
        mOpenCount(0),
        mRecvSocketSet(false),
        mSendSocketSet(false),
        //mOutstandingSendData(0),
        //mMaxOutstandingSendData(0),
        mTotalSentData(0),
        mSendQueueEmptyFuture(mSendQueueEmptyProm.get_future()),
        mRecvQueueEmptyFuture(mRecvQueueEmptyProm.get_future())
#ifdef CHANNEL_LOGGING
        , mRecvIdx(0)
        , mSendIdx(0)
#endif
    {
    }

    ChannelBase::ChannelBase(IOService& ios, SocketInterface * sock)
        :
        mIos(ios),
        mWork(new boost::asio::io_service::work(ios.mIoService)),
        mRecvStatus(Channel::Status::Normal),
        mSendStatus(Channel::Status::Normal),
        mHandle(sock),
        mTimer(ios.mIoService),
        mSendStrand(ios.mIoService),
        mRecvStrand(ios.mIoService),
        mOpenProm(),
        mOpenFut(mOpenProm.get_future()),
        mOpenCount(0),
        mRecvSocketSet(true),
        mSendSocketSet(true),
        //mOutstandingSendData(0),
        //mMaxOutstandingSendData(0),
        mTotalSentData(0),
        mSendQueueEmptyFuture(mSendQueueEmptyProm.get_future()),
        mRecvQueueEmptyFuture(mRecvQueueEmptyProm.get_future())
#ifdef CHANNEL_LOGGING
        , mRecvIdx(0)
        , mSendIdx(0)
#endif
    {
        mOpenProm.set_value();
    }

    Channel::~Channel()
    {
    }


    void ChannelBase::asyncConnectToServer(const boost::asio::ip::tcp::endpoint& address)
    {
        mHandle.reset(new BoostSocketInterface(
            boost::asio::ip::tcp::socket(getIOService().mIoService)));

        mConnectCallback = [this, address](const boost::system::error_code& ec)
        {
            auto& sock = ((BoostSocketInterface*)mHandle.get())->mSock;

            if (ec)
            {
                //std::cout << "connect failed, " << this->mLocalName << " " << ec.value() << " " << ec.message() << ".  " << address.address().to_string() << std::endl;
                // try to connect again...
                if (stopped() == false)
                {
                    mTimer.expires_from_now(boost::posix_time::millisec(10));
                    mTimer.async_wait([&](const boost::system::error_code& ec)
                    {
                        if (ec)
                        {
                            std::cout << "unknown timeout error: " << ec.message() << std::endl;
                        }
                        sock.close();
                        sock.async_connect(address, mConnectCallback);
                    });
                }
                else
                    mOpenProm.set_exception(std::make_exception_ptr(
                        SocketConnectError("Session tried to connect but the channel has stopped. "  LOCATION)));
            }
            else
            {
                boost::asio::ip::tcp::no_delay option(true);
                sock.set_option(option);

                std::stringstream sss;
                sss << mSession->mName << '`'
                    << mSession->mSessionID << '`'
                    << mLocalName << '`'
                    << mRemoteName;
                auto str = sss.str();
                mSendStrand.post([this, str]() mutable
                {
                    using namespace details;
                    auto op = std::make_shared<MoveSendBuff<std::string>>(std::move(str));

                    mSendSocketSet = true;
                    mHasActiveSend = true;

                    auto ii = ++mOpenCount;
                    if (ii == 2) mOpenProm.set_value();

                    op->asyncPerform(this, [this, op](error_code ec, u64 bytesTransferred) {

                        if (ec)
                        {
                            setSendFatalError(LOCATION);
                        }
                        else
                        {
                            mSendStrand.dispatch([this, op]()
                            {
                                mHasActiveSend = false;

                                if (mSendQueue.isEmpty() == false)
                                    asyncPerformSend();
                                else if (mSendStatus == Channel::Status::Stopped)
                                {
                                    mSendQueueEmptyProm.set_value();
                                    mSendQueueEmptyProm = std::promise<void>();
                                }
                            });
                        }
                    });
                });


                mRecvStrand.post([this]()
                {
                    mRecvSocketSet = true;

                    auto ii = ++mOpenCount;
                    if (ii == 2) mOpenProm.set_value();

                    auto startRecv = !mRecvQueue.isEmpty();
#ifdef CHANNEL_LOGGING
                    mLog.push("initRecv' , opened = " + ToString(ii == 2) + ", start = " + ToString(startRecv));
#endif

                    if (startRecv)
                    {
                        asyncPerformRecv();
                    }
                });
            }
        };


        ((BoostSocketInterface*)mHandle.get())->mSock.async_connect(address, mConnectCallback);
    }



    std::string Channel::getName() const
    {
        return mBase->mLocalName;
    }

    Channel & Channel::operator=(Channel && move)
    {
        mBase = std::move(move.mBase);
        return *this;
    }

    Channel & Channel::operator=(const Channel & copy)
    {
        mBase = copy.mBase;
        return *this;
    }

    bool Channel::isConnected()
    {
        return mBase->mSendSocketSet  && mBase->mRecvSocketSet;
    }

    bool Channel::waitForConnection(std::chrono::milliseconds timeout)
    {
        auto status = mBase->mOpenFut.wait_for(timeout);
        if (status != std::future_status::ready)
            return false;
        mBase->mOpenFut.get();
        return true;
    }

    void Channel::waitForConnection()
    {
        mBase->mOpenFut.get();
    }

    void Channel::close()
    {
        if (mBase) mBase->close();
        mBase = nullptr;
    }

    void Channel::cancel()
    {
        if (mBase) mBase->cancel();
    }

    void ChannelBase::cancel()
    {
        if (stopped() == false)
        {
            mSendStatus = Channel::Status::Stopped;
            mRecvStatus = Channel::Status::Stopped;

            if (mHandle) mHandle->close();
            if (mSession && mSession->mAcceptor) mSession->mAcceptor->cancelPendingChannel(this);

            try { mOpenFut.get(); }
            catch (SocketConnectError&)
            {
                // The socket has never started.
                // We can simply remove all the queued items.
                cancelRecvQueuedOperations();
                cancelSendQueuedOperations();
            }

            mSendStrand.dispatch([&]() {
                if (mSendQueue.isEmpty() && mSendQueueEmpty == false)
                    mSendQueueEmptyProm.set_value();
            });

            mRecvStrand.dispatch([&]() {
                if (mRecvQueue.isEmpty() && mRecvQueueEmpty == false)
                    mRecvQueueEmptyProm.set_value();
                else if (activeRecvSizeError())
                    cancelRecvQueuedOperations();
            });

            mSendQueueEmptyFuture.get();
            mRecvQueueEmptyFuture.get();

            mHandle.reset(nullptr);
            mWork.reset(nullptr);
        }

    }


    void ChannelBase::recvEnque(SBO_ptr<details::RecvOperation>&& op)
    {


        mRecvQueue.push_back(std::move(op));

        // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
        mRecvStrand.post([this]()
        {
            // check to see if we should kick off a new set of recv operations. If the size >= 1, then there
            // is already a set of recv operations that will kick off the newly queued recv when its turn comes around.
            bool startRecving = (mHasActiveRecv == false) && mRecvSocketSet;

            // the queue must be guarded from concurrent access, so add the op within the strand
            // queue up the operation.
            if (startRecving)
            {
                // ok, so there isn't any recv operations currently underway. Lets kick off the first one. Subsequent recvs
                // will be kicked off at the completion of this operation.
                asyncPerformRecv();
            }
        });
    }

    void ChannelBase::sendEnque(SBO_ptr<details::SendOperation>&& op)
    {
        mSendQueue.push_back(std::move(op));

        // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
        mSendStrand.post([this]()
        {
            // the queue must be guarded from concurrent access, so add the op within the strand

            // check to see if we should kick off a new set of send operations. If the size >= 1, then there
            // is already a set of send operations that will kick off the newly queued send when its turn comes around.
            auto startSending = (mHasActiveSend == false) && mSendSocketSet;


            if (startSending)
            {
                // ok, so there isn't any send operations currently underway. Lets kick off the first one. Subsequent sends
                // will be kicked off at the completion of this operation.
                asyncPerformSend();
            }
        });
    }


    void ChannelBase::asyncPerformRecv()
    {
        mHasActiveRecv = true;
        mRecvQueue.front()->asyncPerform(this, [this](error_code ec, u64 bytesTransferred) {

            mTotalRecvData += bytesTransferred;

            if (ec)
            {
                auto reason = std::string("network receive error: ") + ec.message() + "\n at  " + LOCATION;
                if (mIos.mPrint) std::cout << reason << std::endl;

                setRecvFatalError(reason);
            }
            else
            {

                mRecvStrand.dispatch([this]()
                {
                    mHasActiveRecv = false;
#ifdef CHANNEL_LOGGING
                    mLog.push("completed recv: " + mRecvQueue.front()->toString());
#endif
                    //delete mRecvQueue.front();
                    mRecvQueue.pop_front();

                    // is there more messages to recv?
                    bool recvMore = !mRecvQueue.isEmpty();

                    if (recvMore)
                    {
                        asyncPerformRecv();
                    }
                    else if (mRecvStatus == Channel::Status::Stopped)
                    {
                        mRecvQueueEmptyProm.set_value();
                        mRecvQueueEmptyProm = std::promise<void>();
                    }
                });
            }
        });
    }

    void ChannelBase::asyncPerformSend()
    {
        mHasActiveSend = true;
        mSendQueue.front()->asyncPerform(this, [this](error_code ec, u64 bytesTransferred) {

            mTotalSentData += bytesTransferred;

            if (ec)
            {
                auto reason = std::string("network send error: ") + ec.message() + "\n at  " + LOCATION;
                if (mIos.mPrint) std::cout << reason << std::endl;

                setSendFatalError(reason);
            }
            else
            {
                mSendStrand.dispatch([this]()
                {
                    mHasActiveSend = false;

#ifdef CHANNEL_LOGGING
                    mLog.push("completed send #" + mSendQueue.front()->toString());
#endif
                    //delete mSendQueue.front();
                    mSendQueue.pop_front();

                    // Do we have more messages to be sent?
                    auto sendMore = !mSendQueue.isEmpty();

                    if (sendMore)
                    {
                        asyncPerformSend();
                    }
                    else if (mSendStatus == Channel::Status::Stopped)
                    {
                        mSendQueueEmptyProm.set_value();
                        mSendQueueEmptyProm = std::promise<void>();
                    }
                });
            }
        });
    }

    void ChannelBase::printError(std::string s)
    {
        mIos.printError(s);
    }


    void ChannelBase::close()
    {
        if (stopped() == false)
        {
            mOpenFut.get();

            mSendStrand.dispatch([&]() {
                mSendStatus = Channel::Status::Stopped;
                if (mSendQueue.isEmpty() && mSendQueueEmpty == false)
                {
                    mSendQueueEmpty = true;
                    mSendQueueEmptyProm.set_value();
                }
            });

            mRecvStrand.dispatch([&]() {
                mRecvStatus = Channel::Status::Stopped;
                if (mRecvQueue.isEmpty() && mRecvQueueEmpty == false)
                {
                    mRecvQueueEmpty = true;
                    mRecvQueueEmptyProm.set_value();
                }
                else if (activeRecvSizeError())
                {
                    cancelRecvQueuedOperations();
                }
            });

            mSendQueueEmptyFuture.get();
            mRecvQueueEmptyFuture.get();

            // ok, the send and recv queues are empty. Lets close the socket
            if (mHandle)mHandle->close();

            mHandle.reset(nullptr);
            mWork.reset(nullptr);

#ifdef CHANNEL_LOGGING
            mLog.push("Closed");
#endif
        }
    }




    void ChannelBase::cancelSendQueuedOperations()
    {
        mSendStrand.dispatch([this]() {

            //if (mHandle)
            //	mHandle->close();
            if (mSendQueueEmpty == false)
            {

                while (!mSendQueue.isEmpty())
                {
                    auto& front = mSendQueue.front();

#ifdef CHANNEL_LOGGING
                    mLog.push("cancel send #" + ToString(front->mIdx));
#endif
                    //delete front->mContainer;

                    front->cancel(mSendErrorMessage);
                    //auto e_ptr = std::make_exception_ptr(std::runtime_error("Channel Error: " + mSendErrorMessage));
                    //front->mPromise.set_exception(e_ptr);

                    //delete front;
                    mSendQueue.pop_front();
                }

#ifdef CHANNEL_LOGGING
                mLog.push("send queue empty");
#endif
                mSendQueueEmpty = true;
                mSendQueueEmptyProm.set_value();
            }
        });
    }


    void ChannelBase::cancelRecvQueuedOperations()
    {
        mRecvStrand.dispatch([this]() {

            if (mRecvQueueEmpty == false)
            {


                //if (mHandle)
                //	mHandle->close();

                while (!mRecvQueue.isEmpty())
                {
                    auto& front = mRecvQueue.front();

#ifdef CHANNEL_LOGGING
                    mLog.push("cancel recv #" + ToString(front->mIdx));
#endif
                    //delete front->mContainer;
                    front->cancel(mRecvErrorMessage);
                    //auto e_ptr = std::make_exception_ptr(std::runtime_error("Channel Error: " + mRecvErrorMessage));
                    //front->mPromise.set_exception(e_ptr);

                    //delete front;
                    mRecvQueue.pop_front();
                }


#ifdef CHANNEL_LOGGING
                mLog.push("recv queue empty");
#endif
                mRecvQueueEmpty = true;
                mRecvQueueEmptyProm.set_value();
            }
        });
    }


    void ChannelBase::startSocket(std::unique_ptr<SocketInterface> socket)
    {

        mHandle = std::move(socket);
        // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
        mRecvStrand.post([this]()
        {


#ifdef CHANNEL_LOGGING
            mLog.push("initRecv , start = " + ToString(mRecvQueue.size()));
#endif

            // check to see if we should kick off a new set of recv operations. Since we are just now
            // starting the channel, its possible that the async connect call returned and the caller scheduled a receive
            // operation. But since the channel handshake just finished, those operations didn't start. So if
            // the queue has anything in it, we should actually start the operation now...
            if (!mRecvQueue.isEmpty())
            {
                // ok, so there isn't any recv operations currently underway. Lets kick off the first one. Subsequent recvs
                // will be kicked off at the completion of this operation.
                asyncPerformRecv();
            }

            mRecvSocketSet = true;

            auto ii = ++mOpenCount;
            if (ii == 2)
                mOpenProm.set_value();
        });


        // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
        mSendStrand.post([this]()
        {
            // the queue must be guarded from concurrent access, so add the op within the strand

            auto start = !mSendQueue.isEmpty();
#ifdef CHANNEL_LOGGING
            mLog.push("initSend , start = " + ToString(start));
#endif
            // check to see if we should kick off a new set of send operations. Since we are just now
            // starting the channel, its possible that the async connect call returned and the caller scheduled a send
            // operation. But since the channel handshake just finished, those operations didn't start. So if
            // the queue has anything in it, we should actually start the operation now...

            if (start)
            {
                // ok, so there isn't any send operations currently underway. Lets kick off the first one. Subsequent sends
                // will be kicked off at the completion of this operation.
                asyncPerformSend();
            }

            mSendSocketSet = true;

            auto ii = ++mOpenCount;
            if (ii == 2)
                mOpenProm.set_value();
        });
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
        //mBase->mMaxOutstandingSendData = 0;
        //mBase->mOutstandingSendData = 0;
    }

    u64 Channel::getTotalDataSent() const
    {
        return mBase->mTotalSentData;
    }

    u64 Channel::getTotalDataRecv() const
    {
        return mBase->mTotalRecvData;
    }

    //u64 Channel::getMaxOutstandingSendData() const
    //{
    //    return (u64)mBase->mMaxOutstandingSendData;
    //}

    //void Channel::dispatch(std::unique_ptr<IOOperation> op)
    //{
    //    mBase->getIOService().dispatch(mBase.get(), std::move(op));
    //}

    void ChannelBase::setRecvFatalError(std::string reason)
    {
        mRecvStrand.dispatch([&, reason]() {

#ifdef CHANNEL_LOGGING
            mLog.push("Recv error: " + reason);
#endif
            mRecvErrorMessage += (reason + "\n");
            mRecvStatus = Channel::Status::Stopped;
            cancelRecvQueuedOperations();
        });
    }

    void ChannelBase::setSendFatalError(std::string reason)
    {
        mSendStrand.dispatch([&, reason]() {

#ifdef CHANNEL_LOGGING
            mLog.push("Send error: " + reason);
#endif
            mSendErrorMessage = reason;
            mSendStatus = Channel::Status::Stopped;
            cancelSendQueuedOperations();
        });
    }

    void ChannelBase::setBadRecvErrorState(std::string reason)
    {
        mRecvStrand.dispatch([&, reason]() {

            if (mRecvStatus == Channel::Status::Normal)
            {
                mRecvErrorMessage = reason;
            }
        });
    }

    void ChannelBase::clearBadRecvErrorState()
    {
        mRecvStrand.dispatch([&]() {

            if (activeRecvSizeError() && mRecvStatus == Channel::Status::Normal)
            {
                mRecvErrorMessage = "";
            }
        });
    }
}
