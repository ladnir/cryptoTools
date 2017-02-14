#include "BtChannel.h"
#include "cryptoTools/Network/BtSocket.h"
#include "cryptoTools/Network/BtEndpoint.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Log.h"

namespace osuCrypto {

    BtChannel::BtChannel(
        BtEndpoint& endpoint,
        std::string localName,
        std::string remoteName)
        :mEndpoint(endpoint),
        mRemoteName(remoteName),
        mLocalName(localName)
    {

    }

    BtChannel::~BtChannel()
    {
    }

    Endpoint & BtChannel::getEndpoint()
    {
        return *(Endpoint*)&mEndpoint;
    }

    std::string BtChannel::getName() const
    {
        return mLocalName;
    }

    void BtChannel::asyncSend(const void * buff, u64 size)
    {
        if (mSocket->mStopped || size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        BoostIOOperation op;

        op.mSize = size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, size);

        op.mType = BoostIOOperation::Type::SendData;

        mEndpoint.getIOService().dispatch(mSocket.get(), op);
    }

    void BtChannel::asyncSend(const void * buff, u64 size, std::function<void()> callback)
    {
        if (mSocket->mStopped || size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        BoostIOOperation op;

        op.mSize = size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, size);

        op.mType = BoostIOOperation::Type::SendData;
        op.mCallback = callback;

        mEndpoint.getIOService().dispatch(mSocket.get(), op);
    }

    void BtChannel::asyncSend(std::unique_ptr<ChannelBuffer> buff)
    {
        if (mSocket->mStopped || buff->ChannelBufferSize() > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        BoostIOOperation op;

        op.mSize = (u32)buff->ChannelBufferSize();


        op.mBuffs[1] = boost::asio::buffer((char*)buff->ChannelBufferData(), buff->ChannelBufferSize());
        op.mType = BoostIOOperation::Type::SendData;

        op.mOther = buff.release();

        mEndpoint.getIOService().dispatch(mSocket.get(), op);
    }

    void BtChannel::send(const void * buff, u64 size)
    {
        if (mSocket->mStopped ||  size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        BoostIOOperation op;
        op.clear();

        op.mSize = (u32)size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, (u32)size);


        op.mType = BoostIOOperation::Type::SendData;

        std::promise<void> prom;
        op.mPromise = &prom;

        mEndpoint.getIOService().dispatch(mSocket.get(), op);

        prom.get_future().get();
    }

    std::future<void> BtChannel::asyncRecv(void * buff, u64 size)
    {
        if (mSocket->mStopped || size > u32(-1))
            throw std::runtime_error("rt error at " LOCATION);

        BoostIOOperation op;
        op.clear();

        op.mSize = size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, size);

        op.mType = BoostIOOperation::Type::RecvData;

        op.mOther = nullptr;

        op.mPromise = new std::promise<void>();
        auto future = op.mPromise->get_future();

        mEndpoint.getIOService().dispatch(mSocket.get(), op);

        return future;
    }

    std::future<void> BtChannel::asyncRecv(ChannelBuffer & mH)
    {
        if (mSocket->mStopped)
            throw std::runtime_error("rt error at " LOCATION);

        BoostIOOperation op;
        op.clear();


        op.mType = BoostIOOperation::Type::RecvData;

        op.mOther = &mH;

        op.mPromise = new std::promise<void>();
        auto future = op.mPromise->get_future();

        mEndpoint.getIOService().dispatch(mSocket.get(), op);

        return future;
    }

    void BtChannel::recv(void * dest, u64 length)
    {
        try {
            // schedule the recv.
            auto request = asyncRecv(dest, length);

            // block until the receive has been completed. 
            // Could throw if the length is wrong.
            request.get();
        }
        catch (BadReceiveBufferSize& bad)
        {
            std::cout << bad.mWhat << std::endl;
            throw;
        }
    }

    void BtChannel::recv(ChannelBuffer & mH)
    {
        asyncRecv(mH).get();
    }

    bool BtChannel::opened()
    {
        return true;
    }
    void BtChannel::waitForOpen()
    {
        // async connect hasn't been implemented.
    }

    void BtChannel::close()
    {
        // indicate that no more messages should be queued and to fulfill
        // the mSocket->mDone* promised.
        mSocket->mStopped = true;


        BoostIOOperation closeRecv;
        closeRecv.mType = BoostIOOperation::Type::CloseRecv;
        std::promise<void> recvPromise;
        closeRecv.mPromise = &recvPromise;

        mEndpoint.getIOService().dispatch(mSocket.get(), closeRecv);

        BoostIOOperation closeSend;
        closeSend.mType = BoostIOOperation::Type::CloseSend;
        std::promise<void> sendPromise;
        closeSend.mPromise = &sendPromise;
        mEndpoint.getIOService().dispatch(mSocket.get(), closeSend);

        recvPromise.get_future().get();
        sendPromise.get_future().get();

        // ok, the send and recv queues are empty. Lets close the socket
        mSocket->mHandle.close();

        // lets de allocate ourselves in the endpoint.
        mEndpoint.removeChannel(getName());

        // WARNING: we are deallocated now. Do not touch any member variables.
    }


    std::string BtChannel::getRemoteName() const
    {
        return mRemoteName;
    }

    void BtChannel::resetStats()
    {
        if (mSocket)
        {
            mSocket->mTotalSentData = 0;
            mSocket->mTotalRecvData = 0;
            mSocket->mMaxOutstandingSendData = 0;
            mSocket->mOutstandingSendData = 0;
        }
    }

    u64 BtChannel::getTotalDataSent() const
    {
        return (mSocket) ? (u64)mSocket->mTotalSentData : 0;
    }

    u64 BtChannel::getTotalDataRecv() const
    {
        return (mSocket) ? (u64)mSocket->mTotalRecvData : 0;
    }

    u64 BtChannel::getMaxOutstandingSendData() const
    {
        return (mSocket) ? (u64)mSocket->mMaxOutstandingSendData : 0;
    }
}
