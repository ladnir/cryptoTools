#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Network/IOService.h>
namespace osuCrypto {

    Channel::Channel(
        Endpoint& endpoint,
        std::string localName,
        std::string remoteName)
        :
        mBase(new ChannelBase(endpoint, localName, remoteName))
    {}

    Channel::Channel(IOService& ios, SocketInterface * sock)
        : mBase(new ChannelBase(ios, sock))
    {}


    ChannelBase::ChannelBase(
        Endpoint& endpoint,
        std::string localName,
        std::string remoteName)
        :
        mIos(endpoint.getIOService()),
        mEndpoint(&endpoint),
        mRemoteName(remoteName),
        mLocalName(localName),
        mId(0),
        mRecvStatus(Channel::Status::Normal),
        mSendStatus(Channel::Status::Normal),
        mHandle(nullptr),
        mSendStrand(endpoint.getIOService().mIoService),
        mRecvStrand(endpoint.getIOService().mIoService),
        mOpenProm(),
        mOpenFut(mOpenProm.get_future()),
        mOpenCount(0),
        mRecvSocketSet(false),
        mSendSocketSet(false),
        mOutstandingSendData(0),
        mMaxOutstandingSendData(0),
        mTotalSentData(0),
        mSendQueueEmptyFuture(mSendQueueEmptyProm.get_future()),
        mRecvQueueEmptyFuture(mRecvQueueEmptyProm.get_future())
#ifdef CHANNEL_LOGGING
        , mOpIdx(0)
#endif
    {
    }

    ChannelBase::ChannelBase(IOService& ios, SocketInterface * sock)
        :
        mIos(ios),
        mEndpoint(nullptr),
        mId(0),
        mRecvStatus(Channel::Status::Normal),
        mSendStatus(Channel::Status::Normal),
        mHandle(sock),
        mSendStrand(ios.mIoService),
        mRecvStrand(ios.mIoService),
        mOpenProm(),
        mOpenFut(mOpenProm.get_future()),
        mOpenCount(0),
        mRecvSocketSet(true),
        mSendSocketSet(true),
        mOutstandingSendData(0),
        mMaxOutstandingSendData(0),
        mTotalSentData(0),
        mSendQueueEmptyFuture(mSendQueueEmptyProm.get_future()),
        mRecvQueueEmptyFuture(mRecvQueueEmptyProm.get_future())
#ifdef CHANNEL_LOGGING
        , mOpIdx(0)
#endif
    {
        mOpenProm.set_value();
    }

    Channel::~Channel()
    {
    }

    Endpoint & Channel::getEndpoint()
    {
        return *mBase->mEndpoint;
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
    void Channel::waitForConnection()
    {
        return mBase->mOpenFut.get();
    }

    void Channel::close()
    {
        // indicate that no more messages should be queued and to fulfill
        // the mSocket->mDone* promised.
        if (mBase)
        {

            mBase->close();
        }
    }
    void ChannelBase::close()
    {


        mOpenFut.get();

        if (mSendStatus != Channel::Status::Stopped)
        {
#ifdef CHANNEL_LOGGING
            mLog.push("Closing send");
#endif

            if (mSendStatus == Channel::Status::Normal)
            {
                auto closeSend = std::unique_ptr<IOOperation>(new IOOperation(IOOperation::Type::CloseSend));
                getIOService().dispatch(this, std::move(closeSend));
            }

            mSendQueueEmptyFuture.get();
            mSendStatus = Channel::Status::Stopped;
        }

        if (mRecvStatus != Channel::Status::Stopped)
        {
#ifdef CHANNEL_LOGGING
            mLog.push("Closing recv");
#endif

            if (mRecvStatus == Channel::Status::Normal)
            {
                auto closeRecv = std::unique_ptr<IOOperation>(new IOOperation(IOOperation::Type::CloseRecv));
                getIOService().dispatch(this, std::move(closeRecv));
            }
            else if (mRecvStatus == Channel::Status::RecvSizeError)
            {
                cancelRecvQueuedOperations();
            }

            mRecvQueueEmptyFuture.get();
            mRecvStatus = Channel::Status::Stopped;
        }

        // ok, the send and recv queues are empty. Lets close the socket
        if (mHandle)
        {
            if (mEndpoint) mEndpoint->removeChannel(this);
            mHandle->close();
            mHandle.reset(nullptr);
        }

#ifdef CHANNEL_LOGGING
        mLog.push("Closed");
#endif
    }


    void ChannelBase::cancelSendQueuedOperations()
    {

        mHandle->close();

        while (mSendQueue.size())
        {
            auto& front = mSendQueue.front();

#ifdef CHANNEL_LOGGING
            mLog.push("cancel send #" + ToString(front->mIdx));
#endif
            //delete front->mContainer;

            auto e_ptr = std::make_exception_ptr(std::runtime_error("Channel Error: " + mSendErrorMessage));
            front->mPromise.set_exception(e_ptr);

            //delete front;
            mSendQueue.pop_front();
        }

#ifdef CHANNEL_LOGGING
        mLog.push("send queue empty");
#endif
        mSendQueueEmptyProm.set_value();
    }


    void ChannelBase::cancelRecvQueuedOperations()
    {
        mHandle->close();

        while (mRecvQueue.size())
        {
            auto& front = mRecvQueue.front();

#ifdef CHANNEL_LOGGING
            mLog.push("cancel recv #" + ToString(front->mIdx));
#endif
            //delete front->mContainer;

            auto e_ptr = std::make_exception_ptr(std::runtime_error("Channel Error: " + mRecvErrorMessage));
            front->mPromise.set_exception(e_ptr);

            //delete front;
            mRecvQueue.pop_front();
        }


#ifdef CHANNEL_LOGGING
        mLog.push("recv queue empty");
#endif
        mRecvQueueEmptyProm.set_value();
    }

    std::string Channel::getRemoteName() const
    {
        return mBase->mRemoteName;
    }

    void Channel::resetStats()
    {
        mBase->mTotalSentData = 0;
		mBase->mTotalRecvData = 0;
        mBase->mMaxOutstandingSendData = 0;
        mBase->mOutstandingSendData = 0;
    }

    u64 Channel::getTotalDataSent() const
    {
        return mBase->mTotalSentData;
    }

    u64 Channel::getTotalDataRecv() const
    {
        return mBase->mTotalRecvData;
    }

    u64 Channel::getMaxOutstandingSendData() const
    {
        return (u64)mBase->mMaxOutstandingSendData;
    }


    void Channel::dispatch(std::unique_ptr<IOOperation> op)
    {
        mBase->getIOService().dispatch(mBase.get(), std::move(op));
    }

    void ChannelBase::setRecvFatalError(std::string reason)
    {
#ifdef CHANNEL_LOGGING
        mLog.push("Recv error: " + reason);
#endif
        mRecvErrorMessage += (reason + "\n");
        mRecvStatus = Channel::Status::FatalError;
        cancelRecvQueuedOperations();
    }

    void ChannelBase::setSendFatalError(std::string reason)
    {
#ifdef CHANNEL_LOGGING
        mLog.push("Send error: " + reason);
#endif
        mSendErrorMessage = reason;
        mSendStatus = Channel::Status::FatalError;
        cancelSendQueuedOperations();
    }

    void ChannelBase::setBadRecvErrorState(std::string reason)
    {
        if (mRecvStatus != Channel::Status::Normal)
        {
            std::cout << "Double Error in Channel::setBadRecvErrorState, Channel: " << mLocalName << "\n   " << LOCATION << "\n error set twice." << std::endl;
            std::terminate();
        }
        mRecvErrorMessage = reason;
        mRecvStatus = Channel::Status::RecvSizeError;
    }

    void ChannelBase::clearBadRecvErrorState()
    {

        if (mRecvStatus != Channel::Status::RecvSizeError)
        {
            std::cout << "Error in Channel::clearBadRecvErrorState, Channel: " << mLocalName << "\n   " << LOCATION << "\n Was not in Status::RecvSizeError." << std::endl;
            std::terminate();
        }

        mSendErrorMessage = "";
        mRecvStatus = Channel::Status::Normal;
    }
}
