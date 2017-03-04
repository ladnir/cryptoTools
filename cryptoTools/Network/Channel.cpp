#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/IoBuffer.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/ByteStream.h>

namespace osuCrypto {

    Channel::Channel(
        Endpoint& endpoint,
        std::string localName,
        std::string remoteName)
        :
        mBase(new ChannelBase(endpoint, localName, remoteName))
    {}


    ChannelBase::ChannelBase(
        Endpoint& endpoint,
        std::string localName,
        std::string remoteName)
        :
        mEndpoint(endpoint),
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

    Channel::~Channel()
    {
    }

    Endpoint & Channel::getEndpoint()
    {
        return mBase->mEndpoint;
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

    void Channel::asyncSend(const void * buff, u64 size)
    {
        if (mBase->mSendStatus != Status::Normal || size == 0 || size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        IOOperation op;

        op.mSize = (u32)size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, (u32)size);

        op.mType = IOOperation::Type::SendData;

        mBase->mEndpoint.getIOService().dispatch(mBase.get(), op);
    }

    void Channel::asyncSend(const void * buff, u64 size, std::function<void()> callback)
    {
        if (mBase->mSendStatus != Status::Normal || size == 0 || size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        IOOperation op;

        op.mSize = u32(size);
        op.mBuffs[1] = boost::asio::buffer((char*)buff, size);

        op.mType = IOOperation::Type::SendData;
        op.mCallback = callback;

        dispatch(op);
    }

    void Channel::send(const void * buff, u64 size)
    {
        if (mBase->mSendStatus != Status::Normal || size == 0 || size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        IOOperation op;

        op.mSize = (u32)size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, (u32)size);


        op.mType = IOOperation::Type::SendData;

        std::promise<u64> prom;
        op.mPromise = &prom;

        mBase->mEndpoint.getIOService().dispatch(mBase.get(), op);

        prom.get_future().get();
    }

    std::future<u64> Channel::asyncRecv(void * buff, u64 size)
    {
        if (mBase->mSendStatus != Status::Normal || size == 0 || size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        IOOperation op;

        op.mSize = (u32)size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, (u32)size);

        op.mType = IOOperation::Type::RecvData;

        op.mContainer = nullptr;

        op.mPromise = new std::promise<u64>();
        auto future = op.mPromise->get_future();

        mBase->mEndpoint.getIOService().dispatch(mBase.get(), op);

        return future;
    }

    u64 Channel::recv(void * dest, u64 length)
    {
        try {
            // schedule the recv.
            auto request = asyncRecv(dest, length);

            // block until the receive has been completed. 
            // Could throw if the length is wrong.
            return request.get();
        }
        catch (BadReceiveBufferSize& bad)
        {
            std::cout << bad.mWhat << std::endl;
            throw;
        }
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
                IOOperation closeSend;
                closeSend.mType = IOOperation::Type::CloseSend;
                closeSend.mPromise = &mSendQueueEmptyProm;
                mEndpoint.getIOService().dispatch(this, closeSend);
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
                IOOperation closeRecv;
                closeRecv.mType = IOOperation::Type::CloseRecv;
                closeRecv.mPromise = &mRecvQueueEmptyProm;
                mEndpoint.getIOService().dispatch(this, closeRecv);
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
            mEndpoint.removeChannel(this);
            mHandle->close();
            mHandle = nullptr;
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
            mLog.push("cancel send #" + ToString(front.mIdx));
#endif
            delete front.mContainer;

            if (front.mPromise)
            {
                auto e_ptr = std::make_exception_ptr(NetworkError("Channel Error: " + mSendErrorMessage));
                front.mPromise->set_exception(e_ptr);
            }

            mSendQueue.pop_front();
        }

#ifdef CHANNEL_LOGGING
        mLog.push("send queue empty");
#endif
        mSendQueueEmptyProm.set_value(0);



//        mRecvStrand.post([this]
//        {
//            if (mRecvQueue.size() == 0)
//            {
//
//#ifdef CHANNEL_LOGGING
//                mLog.push("recv queue empty");
//#endif
//                mRecvQueueEmptyProm.set_value(0);
//            }
//            else
//            {
//#ifdef CHANNEL_LOGGING
//                mLog.push("recv queue size " + ToString(mRecvQueue.size()));
//#endif
//            }
//
//        });
    }

    void ChannelBase::cancelRecvQueuedOperations()
    {
        mHandle->close();

        while (mRecvQueue.size())
        {
            auto& front = mRecvQueue.front();

#ifdef CHANNEL_LOGGING
            mLog.push("cancel recv #" + ToString(front.mIdx));
#endif
            delete front.mContainer;

            if (front.mPromise)
            {
                auto e_ptr = std::make_exception_ptr(NetworkError("Channel Error: " + mRecvErrorMessage));
                front.mPromise->set_exception(e_ptr);
            }

            mRecvQueue.pop_front();
        }


#ifdef CHANNEL_LOGGING
        mLog.push("recv queue empty");
#endif
        mRecvQueueEmptyProm.set_value(0);

//        mSendStrand.post([this]
//        {
//            if (mSendQueue.size() == 0)
//            {
//
//#ifdef CHANNEL_LOGGING
//                mLog.push("send queue empty");
//#endif
//                mSendQueueEmptyProm.set_value(0);
//            }
//            else
//            {
//#ifdef CHANNEL_LOGGING
//                mLog.push("send queue size " + ToString(mSendQueue.size()));
//#endif
//            }
//        });

    }

    std::string Channel::getRemoteName() const
    {
        return mBase->mRemoteName;
    }

    void Channel::resetStats()
    {
        mBase->mTotalSentData = 0;
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

    void Channel::asyncSendCopy(const void * bufferPtr, u64 length)
    {
        ByteStream bs((u8*)bufferPtr, length);
        asyncSend(std::move(bs));
    }

    void Channel::dispatch(IOOperation & op)
    {
        mBase->mEndpoint.getIOService().dispatch(mBase.get(), op);
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
