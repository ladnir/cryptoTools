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
        mHandle(nullptr),
        mSendStrand(endpoint.getIOService().mIoService),
        mRecvStrand(endpoint.getIOService().mIoService),
        mOpenProm(),
        mOpenFut(mOpenProm.get_future()),
        mOpenCount(0),
        mRecvSocketSet(false),
        mSendSocketSet(false),
        mStatus(Channel::Status::Normal),
        mId(0),
        mOutstandingSendData(0),
        mMaxOutstandingSendData(0),
        mTotalSentData(0),
        mSendQueueEmptyFuture(mSendQueueEmptyProm.get_future()),
        mRecvQueueEmptyFuture(mRecvQueueEmptyProm.get_future())
    {

    }

    Channel::~Channel()
    {
        close();
        //std::cout << IoStream::lock << "deleting handle: " << mHandle.get() << std::endl << IoStream::unlock;
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
        if (mBase->mStatus != Status::Normal || size == 0 || size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        IOOperation op;

        op.mSize = (u32)size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, (u32)size);

        op.mType = IOOperation::Type::SendData;

        mBase->mEndpoint.getIOService().dispatch(mBase.get(), op);
    }

    void Channel::asyncSend(const void * buff, u64 size, std::function<void()> callback)
    {
        if (mBase->mStatus != Status::Normal || size == 0 || size > u32(-1))
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
        if (mBase->mStatus != Status::Normal || size == 0 || size > u32(-1))
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
        if (mBase->mStatus != Status::Normal || size == 0 || size > u32(-1))
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


            auto status = mBase->mStatus;


            if (status != Status::Stopped)
            {
                mBase->mStatus = Status::Stopped;

                if (status == Status::Normal)
                {
                    IOOperation closeRecv;
                    closeRecv.mType = IOOperation::Type::CloseRecv;
                    closeRecv.mPromise = &mBase->mRecvQueueEmptyProm;

                    mBase->mEndpoint.getIOService().dispatch(mBase.get(), closeRecv);

                    IOOperation closeSend;
                    closeSend.mType = IOOperation::Type::CloseSend;
                    closeSend.mPromise = &mBase->mSendQueueEmptyProm;
                    mBase->mEndpoint.getIOService().dispatch(mBase.get(), closeSend);

                }
                else if (status == Status::RecvSizeError)
                {
                    mBase->cancelQueuedOperations();
                }

                mBase->mRecvQueueEmptyFuture.get();
                mBase->mSendQueueEmptyFuture.get();

                // ok, the send and recv queues are empty. Lets close the socket
                if (mBase->mHandle)
                    mBase->mHandle->close();

                // notify the endpoint.
                mBase->mEndpoint.removeChannel(mBase.get());
            }
        }
    }



    void ChannelBase::cancelQueuedOperations()
    {
        mSendStrand.post([this]()
        {

            while (mSendQueue.size())
            {
                auto& front = mSendQueue.front();

                delete front.mContainer;

                if (front.mPromise)
                {
                    auto e_ptr = std::make_exception_ptr(NetworkError("Channel Error: " + mErrorMessage));
                    front.mPromise->set_exception(e_ptr);
                }

                mSendQueue.pop_front();
            }
            mSendQueueEmptyProm.set_value(0);
        });

        mRecvStrand.post([this]()
        {
            while (mRecvQueue.size())
            {
                auto& front = mRecvQueue.front();

                delete front.mContainer;

                if (front.mPromise)
                {
                    auto e_ptr = std::make_exception_ptr(NetworkError("Channel Error: " + mErrorMessage));
                    front.mPromise->set_exception(e_ptr);
                }

                mRecvQueue.pop_front();
            }
            mRecvQueueEmptyProm.set_value(0);

        });


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
        std::unique_ptr<ByteStream> bs(new ByteStream((u8*)bufferPtr, length));
        asyncSend(std::move(bs));
    }

    void Channel::dispatch(IOOperation & op)
    {
        mBase->mEndpoint.getIOService().dispatch(mBase.get(), op);
    }

    void ChannelBase::setFatalError(std::string reason)
    {
        if (mStatus != Channel::Status::Normal)
        {
            std::cout << "Double Error in Channel::setFatalError, Channel: " << mLocalName << "\n   " << LOCATION << "\n error set twice." << std::endl;
            std::terminate();
        }

        mErrorMessage = reason;
        mStatus = Channel::Status::FatalError;

        cancelQueuedOperations();
    }

    void ChannelBase::setBadRecvErrorState(std::string reason)
    {
        if (mStatus != Channel::Status::Normal)
        {
            std::cout << "Double Error in Channel::setBadRecvErrorState, Channel: " << mLocalName << "\n   " << LOCATION << "\n error set twice." << std::endl;
            std::terminate();
        }
        mErrorMessage = reason;
        mStatus = Channel::Status::RecvSizeError;
    }

    void ChannelBase::clearBadRecvErrorState()
    {

        if (mStatus != Channel::Status::RecvSizeError)
        {
            std::cout << "Error in Channel::clearBadRecvErrorState, Channel: " << mLocalName << "\n   " << LOCATION << "\n Was not in Status::RecvSizeError." << std::endl;
            std::terminate();
        }

        mErrorMessage = "";
        mStatus = Channel::Status::Normal;
    }


}
