#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/BtSocket.h>
#include <cryptoTools/Network/BtEndpoint.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/ByteStream.h>

namespace osuCrypto {

    Channel::Channel(
        BtEndpoint& endpoint,
        std::string localName,
        std::string remoteName)
        :mEndpoint(endpoint),
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
        mStatus(Status::Normal),
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
        //std::cout << IoStream::lock << "deleting handle: " << mHandle.get() << std::endl << IoStream::unlock;
    }

    Endpoint & Channel::getEndpoint()
    {
        return *(Endpoint*)&mEndpoint;
    }

    std::string Channel::getName() const
    {
        return mLocalName;
    }

    void Channel::asyncSend(const void * buff, u64 size)
    {
        if (mStatus != Status::Normal || size == 0 || size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        BtIOOperation op;

        op.mSize = (u32)size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, (u32)size);

        op.mType = BtIOOperation::Type::SendData;

        mEndpoint.getIOService().dispatch(this, op);
    }

    void Channel::asyncSend(const void * buff, u64 size, std::function<void()> callback)
    {
        if (mStatus != Status::Normal || size == 0 || size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        BtIOOperation op;

        op.mSize = u32(size);
        op.mBuffs[1] = boost::asio::buffer((char*)buff, size);

        op.mType = BtIOOperation::Type::SendData;
        op.mCallback = callback;

        dispatch(op);
    }

    void Channel::send(const void * buff, u64 size)
    {
        if (mStatus != Status::Normal || size == 0 || size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        BtIOOperation op;

        op.mSize = (u32)size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, (u32)size);


        op.mType = BtIOOperation::Type::SendData;

        std::promise<u64> prom;
        op.mPromise = &prom;

        mEndpoint.getIOService().dispatch(this, op);

        prom.get_future().get();
    }

    std::future<u64> Channel::asyncRecv(void * buff, u64 size)
    {
        if (mStatus != Status::Normal || size == 0 || size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        BtIOOperation op;

        op.mSize = (u32)size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, (u32)size);

        op.mType = BtIOOperation::Type::RecvData;

        op.mContainer = nullptr;

        op.mPromise = new std::promise<u64>();
        auto future = op.mPromise->get_future();

        mEndpoint.getIOService().dispatch(this, op);

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
        return mSendSocketSet  && mRecvSocketSet;
    }
    void Channel::waitForConnection()
    {
        return mOpenFut.get();
    }

    void Channel::close()
    {
        // indicate that no more messages should be queued and to fulfill
        // the mSocket->mDone* promised.

        auto status = mStatus;
        mStatus = Status::Stopped;

        if (status == Status::Normal)
        {
            BtIOOperation closeRecv;
            closeRecv.mType = BtIOOperation::Type::CloseRecv;
            closeRecv.mPromise = &mRecvQueueEmptyProm;

            mEndpoint.getIOService().dispatch(this, closeRecv);

            BtIOOperation closeSend;
            closeSend.mType = BtIOOperation::Type::CloseSend;
            closeSend.mPromise = &mSendQueueEmptyProm;
            mEndpoint.getIOService().dispatch(this, closeSend);

        }
        else if( status == Status::RecvSizeError)
        {
            cancelQueuedOperations();
        }

        mRecvQueueEmptyFuture.get();
        mSendQueueEmptyFuture.get();

        // ok, the send and recv queues are empty. Lets close the socket
        if (mHandle)
            mHandle->close();

        // lets de allocate ourselves in the endpoint.
        mEndpoint.removeChannel(getName());

        // WARNING: we are deallocated now. Do not touch any member variables.
    }



    void Channel::cancelQueuedOperations()
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
        return mRemoteName;
    }

    void Channel::resetStats()
    {
        mTotalSentData = 0;
        mMaxOutstandingSendData = 0;
        mOutstandingSendData = 0;
    }

    u64 Channel::getTotalDataSent() const
    {
        return mTotalSentData;
    }

    u64 Channel::getTotalDataRecv() const
    {
        return mTotalRecvData;
    }

    u64 Channel::getMaxOutstandingSendData() const
    {
        return (u64)mMaxOutstandingSendData;
    }

    void Channel::asyncSendCopy(const void * bufferPtr, u64 length)
    {
        std::unique_ptr<ByteStream> bs(new ByteStream((u8*)bufferPtr, length));
        asyncSend(std::move(bs));
    }

    void Channel::dispatch(BtIOOperation & op)
    {
        mEndpoint.getIOService().dispatch(this, op);
    }

    void Channel::setFatalError(std::string reason)
    {
        if (mStatus != Status::Normal)
        {
            std::cout << "Double Error in Channel::setFatalError, Channel: " << getName() << "\n   " << LOCATION << "\n error set twice." << std::endl;
            std::terminate();
        }

        mErrorMessage = reason;
        mStatus = Status::FatalError;

        cancelQueuedOperations();
    }

    void Channel::setBadRecvErrorState(std::string reason)
    {
        if (mStatus != Status::Normal)
        {
            std::cout << "Double Error in Channel::setBadRecvErrorState, Channel: " << getName() << "\n   " << LOCATION << "\n error set twice." << std::endl;
            std::terminate();
        }
        mErrorMessage = reason;
        mStatus = Status::RecvSizeError;
    }

    void Channel::clearBadRecvErrorState()
    {

        if (mStatus != Status::RecvSizeError)
        {
            std::cout << "Error in Channel::clearBadRecvErrorState, Channel: " << getName() << "\n   " << LOCATION << "\n Was not in Status::RecvSizeError." << std::endl;
            std::terminate();
        }

        mErrorMessage = "";
        mStatus = Status::Normal;
    }


}
