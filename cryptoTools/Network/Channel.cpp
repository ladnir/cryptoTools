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
        mTimer(endpoint.getIOService().mIoService),
        mSendStrand(endpoint.getIOService().mIoService),
        mRecvStrand(endpoint.getIOService().mIoService),
        mOpenProm(),
        mOpenFut(mOpenProm.get_future()),
        mOpenCount(0),
        mSendQueueEmptyFuture(mSendQueueEmptyProm.get_future()),
        mRecvQueueEmptyFuture(mRecvQueueEmptyProm.get_future())
    {
    }

    ChannelBase::ChannelBase(IOService& ios, SocketInterface * sock)
        :
        mIos(ios),
        mWork(new boost::asio::io_service::work(ios.mIoService)),
        mHandle(sock),
        mTimer(ios.mIoService),
        mSendStrand(ios.mIoService),
        mRecvStrand(ios.mIoService),
        mOpenProm(),
        mOpenFut(mOpenProm.get_future()),
        mOpenCount(0),
        mSendSocketAvailable(true),
        mRecvSocketAvailable(true),
        mSendQueueEmptyFuture(mSendQueueEmptyProm.get_future()),
        mRecvQueueEmptyFuture(mRecvQueueEmptyProm.get_future())
    {
        mOpenProm.set_value();
    }

    Channel::~Channel()
    {
    }


#ifdef CHANNEL_LOGGING
#define LOG_MSG(m) mLog.push(m);
#else
#define LOG_MSG(m)
#endif

    void ChannelBase::asyncConnectToServer(const boost::asio::ip::tcp::endpoint& address)
    {
        LOG_MSG("start async connect to server");

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
                    LOG_MSG("retry async connect to server");
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
                {
                    LOG_MSG("failed async connect to server. Channel stopped by user.");
                    mOpenProm.set_exception(std::make_exception_ptr(
                        SocketConnectError("Session tried to connect but the channel has stopped. "  LOCATION)));
                }
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


                LOG_MSG("Success: async connect to server. ConnectionString = " + str);


                mSendStrand.dispatch([this, str]() mutable
                {
                    LOG_MSG("async connect. Sending ConnectionString");
                    using namespace details;
                    auto op = std::make_shared<MoveSendBuff<std::string>>(std::move(str));

                    auto ii = ++mOpenCount;
                    if (ii == 2) mOpenProm.set_value();

                    op->asyncPerform(this, [this, op](error_code ec, u64 bytesTransferred) {

                        if (ec)
                        {
                            LOG_MSG("async connect. Failed to send ConnectionString");
                            setSendFatalError(LOCATION);
                        }
                        else
                        {
                            LOG_MSG("async connect. ConnectionString sent.");

                            mSendStrand.dispatch([this]()
                            {
                                mSendSocketAvailable = true;


                                if (mSendQueue.isEmpty() == false)
                                {
                                    asyncPerformSend();
                                }
                                else
                                {
                                    LOG_MSG("async connect. queue is empty.");

                                    if (mSendStatus == Channel::Status::Stopped && 
                                        mSendQueueEmpty == false)
                                    {
                                        mSendQueueEmpty = true;
                                        mSendQueueEmptyProm.set_value();
                                        mSendQueueEmptyProm = std::promise<void>();
                                    }
                                }
                            });
                        }
                    });
                });


                mRecvStrand.dispatch([this]()
                {
                    auto ii = ++mOpenCount;
                    if (ii == 2) mOpenProm.set_value();
                    mRecvSocketAvailable = true;

                    if (!mRecvQueue.isEmpty())
                    {
                        LOG_MSG("async connect. Recv Strand, start.");
                        asyncPerformRecv();
                    }
                    else
                    {
                        LOG_MSG("async connect. Recv Strand, queue empty.");
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
        return mBase->mOpenCount == 2;
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
        LOG_MSG("cancel()");


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
                {
                    mSendQueueEmpty = true;
                    mSendQueueEmptyProm.set_value();
                }
            });

            mRecvStrand.dispatch([&]() {
                if (mRecvQueue.isEmpty() && mRecvQueueEmpty == false)
                {
                    mRecvQueueEmpty = true;
                    mRecvQueueEmptyProm.set_value();
                }
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
#ifdef CHANNEL_LOGGING
        op->mIdx = mRecvIdx++;
#endif

        LOG_MSG("queuing Recv op " + op->toString());

        mRecvQueue.push_back(std::move(op));

        // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
        mRecvStrand.post([this]()
        {


            // check to see if we should kick off a new set of recv operations. If the size >= 1, then there
            // is already a set of recv operations that will kick off the newly queued recv when its turn comes around.
            bool hasItems = (mRecvQueue.isEmpty() == false);
            bool startRecving = hasItems && mRecvSocketAvailable;

            LOG_MSG("queuing* Recv, start = " + ToString(startRecving) + " = " + ToString(hasItems) + " & " + ToString(mRecvSocketAvailable));
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

#ifdef CHANNEL_LOGGING
        op->mIdx = mSendIdx++;
#endif
        LOG_MSG("queuing Send op " + op->toString());

        mSendQueue.push_back(std::move(op));

        // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
        mSendStrand.post([this]()
        {
            auto hasItems = (mSendQueue.isEmpty() == false);
            auto startSending = hasItems && mSendSocketAvailable;

            LOG_MSG("queuing* Send, start = " + ToString(startSending) + " = " + ToString(hasItems)
                + " & " + ToString(mSendSocketAvailable));

            if (startSending)
            {
                asyncPerformSend();
            }
        });
    }


    void ChannelBase::asyncPerformRecv()
    {
        LOG_MSG("starting asyncPerformRecv()");

        if (mRecvSocketAvailable == false)
            throw std::runtime_error(LOCATION);

        mRecvSocketAvailable = false;
        mIos.mIoService.dispatch([this] {

            mRecvQueue.front()->asyncPerform(this, [this](error_code ec, u64 bytesTransferred) {

                mTotalRecvData += bytesTransferred;

                if (ec)
                {
                    auto reason = std::string("network receive error: ") + ec.message() + "\n at  " + LOCATION;
                    LOG_MSG(reason);
                    setRecvFatalError(reason);
                }
                else
                {
                    mRecvStrand.dispatch([this]()
                    {
                        LOG_MSG("completed recv: " + mRecvQueue.front()->toString());

                        mRecvSocketAvailable = true;
                        mRecvQueue.pop_front();

                        // is there more messages to recv?
                        if (!mRecvQueue.isEmpty())
                        {
                            asyncPerformRecv();
                        }
                        else if (mRecvStatus == Channel::Status::Stopped && 
                            mRecvQueueEmpty == false)
                        {
                            LOG_MSG("Recv queue stopped.");
                            mRecvQueueEmpty = true;
                            mRecvQueueEmptyProm.set_value();
                            mRecvQueueEmptyProm = std::promise<void>();
                        }
                    });
                }
            });
        });
    }

    void ChannelBase::asyncPerformSend()
    {
        LOG_MSG("Starting asyncPerformSend()");

        if (mSendSocketAvailable == false)
        {
#ifdef CHANNEL_LOGGING
            std::cout << mLog << std::endl;
#endif
            throw std::runtime_error(LOCATION);
        }

        mSendSocketAvailable = false;
        mIos.mIoService.dispatch([this] {
            mSendQueue.front()->asyncPerform(this, [this](error_code ec, u64 bytesTransferred) {

                mTotalSentData += bytesTransferred;

                if (ec)
                {
                    auto reason = std::string("network send error: ") + ec.message() + "\n at  " + LOCATION;
                    LOG_MSG(reason);
                    setSendFatalError(reason);
                }
                else
                {
                    mSendStrand.dispatch([this]()
                    {
                        LOG_MSG("completed send #" + mSendQueue.front()->toString());

                        mSendSocketAvailable = true;
                        mSendQueue.pop_front();

                        if (!mSendQueue.isEmpty())
                        {
                            asyncPerformSend();
                        }
                        else if (mSendStatus == Channel::Status::Stopped && mSendQueueEmpty == false)
                        {
                            LOG_MSG("Send queue stopped");
                            mSendQueueEmpty = true;
                            mSendQueueEmptyProm.set_value();
                            mSendQueueEmptyProm = std::promise<void>();
                        }
                    });
                }
            });
        });
    }

    void ChannelBase::printError(std::string s)
    {
        LOG_MSG(s);
        mIos.printError(s);
    }


    void ChannelBase::close()
    {
        LOG_MSG("Closing...");

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

        }
        LOG_MSG("Closed");
    }




    void ChannelBase::cancelSendQueuedOperations()
    {
        mSendStrand.dispatch([this]()
        {
            if (mSendQueueEmpty == false)
            {
                while (!mSendQueue.isEmpty())
                {
                    auto& front = mSendQueue.front();
                    LOG_MSG("cancel send #" + ToString(front->mIdx));
                    front->cancel(mSendErrorMessage);
                    mSendQueue.pop_front();
                }

                LOG_MSG("send queue empty");
                mSendQueueEmpty = true;
                mSendQueueEmptyProm.set_value();
            }
        });
    }


    void ChannelBase::cancelRecvQueuedOperations()
    {
        mRecvStrand.dispatch([this]()
        {
            if (mRecvQueueEmpty == false)
            {
                while (!mRecvQueue.isEmpty())
                {
                    auto& front = mRecvQueue.front();
                    LOG_MSG("cancel recv #" + ToString(front->mIdx));
                    front->cancel(mRecvErrorMessage);
                    mRecvQueue.pop_front();
                }

                LOG_MSG("recv queue empty");
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
            auto ii = ++mOpenCount;
            if (ii == 2)
                mOpenProm.set_value();
            
            mRecvSocketAvailable = true;

            bool isEmpty = mRecvQueue.isEmpty();
            LOG_MSG("startSocket Recv, queue is isEmpty = " + ToString(isEmpty));

            if (isEmpty == false)
            {
                asyncPerformRecv();
            }
        });


        // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
        mSendStrand.post([this]()
        {
            auto ii = ++mOpenCount;
            if (ii == 2)
                mOpenProm.set_value();
            mSendSocketAvailable = true;

            bool isEmpty = mSendQueue.isEmpty();
            LOG_MSG("startSocket Send, queue is isEmpty = " + ToString(isEmpty));

            if (!isEmpty)
            {
                // ok, so there isn't any send operations currently underway. Lets kick off the first one. Subsequent sends
                // will be kicked off at the completion of this operation.
                asyncPerformSend();
            }
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

        if (mIos.mPrint)
            std::cout << reason << std::endl;

        mRecvStrand.dispatch([&, reason]() {

            LOG_MSG("Recv error: " + reason);
            mRecvErrorMessage += (reason + "\n");
            mRecvStatus = Channel::Status::Stopped;
            cancelRecvQueuedOperations();
        });
    }

    void ChannelBase::setSendFatalError(std::string reason)
    {
        if (mIos.mPrint)
            std::cout << reason << std::endl;

        mSendStrand.dispatch([&, reason]() {

            LOG_MSG("Send error: " + reason);
            mSendErrorMessage = reason;
            mSendStatus = Channel::Status::Stopped;
            cancelSendQueuedOperations();
        });
    }

    void ChannelBase::setBadRecvErrorState(std::string reason)
    {
        if (mIos.mPrint)
            std::cout << reason << std::endl;

        mRecvStrand.dispatch([&, reason]() {

            LOG_MSG("Recv bad buff size: " + reason);
            if (mRecvStatus == Channel::Status::Normal)
            {
                mRecvErrorMessage = reason;
            }
        });
    }

    void ChannelBase::clearBadRecvErrorState()
    {
        mRecvStrand.dispatch([&]() {
            LOG_MSG("Recv clear bad buff size: ");

            if (activeRecvSizeError() && mRecvStatus == Channel::Status::Normal)
            {
                mRecvErrorMessage = {};
            }
        });
    }
}
