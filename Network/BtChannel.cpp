#include "BtChannel.h"
#include "Network/BtSocket.h"
#include "Network/BtEndpoint.h"
#include  "Common/Defines.h"
#include "Common/Log.h"

namespace osuCrypto {

    BtChannel::BtChannel(
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
        mStopped(false),
        mRecvSocketSet(false),
        mSendSocketSet(false),
        mId(0),
        mOutstandingSendData(0),
        mMaxOutstandingSendData(0),
        mTotalSentData(0)
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
        if (mStopped)
            throw std::runtime_error("rt error at " LOCATION);

        BtIOOperation op;

        op.mSize = (u32)size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, (u32)size);

        op.mType = BtIOOperation::Type::SendData;

        mEndpoint.getIOService().dispatch(this, op);
    }

    void BtChannel::asyncSend(std::unique_ptr<ChannelBuffer> buff)
    {
        if (mStopped)
            throw std::runtime_error("rt error at " LOCATION);

        BtIOOperation op;

        op.mSize = (u32)buff->ChannelBufferSize();


        op.mBuffs[1] = boost::asio::buffer((char*)buff->ChannelBufferData(), (u32)buff->ChannelBufferSize());
        op.mType = BtIOOperation::Type::SendData;

        op.mOther = buff.release();

        mEndpoint.getIOService().dispatch(this, op);
    }

    void BtChannel::asyncSend(const void * buff, u64 size, std::function<void(void)> callback)
    {
        if (mStopped)
            throw std::runtime_error("rt error at " LOCATION);

        BtIOOperation op;

        op.mSize = (u32)size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, (u32)size);

        op.mType = BtIOOperation::Type::SendData;
        op.mCallback = callback;

        mEndpoint.getIOService().dispatch(this, op);
    }

    void BtChannel::send(const void * buff, u64 size)
    {
        if (mStopped)
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

    std::future<u64> BtChannel::asyncRecv(void * buff, u64 size)
    {
        if (mStopped)
            throw std::runtime_error("rt error at " LOCATION);

        BtIOOperation op;

        op.mSize = (u32)size;
        op.mBuffs[1] = boost::asio::buffer((char*)buff, (u32)size);

        op.mType = BtIOOperation::Type::RecvData;

        op.mOther = nullptr;

        op.mPromise = new std::promise<u64>();
        auto future = op.mPromise->get_future();

        mEndpoint.getIOService().dispatch(this, op);

        return future;
    }

    std::future<u64> BtChannel::asyncRecv(ChannelBuffer & mH)
    {
        if (mStopped)
            throw std::runtime_error("rt error at " LOCATION);

        BtIOOperation op;


        op.mType = BtIOOperation::Type::RecvData;

        op.mOther = &mH;

        op.mPromise = new std::promise<u64>();
        auto future = op.mPromise->get_future();

        mEndpoint.getIOService().dispatch(this, op);

        return future;
    }

    u64 BtChannel::recv(void * dest, u64 length)
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

    u64 BtChannel::recv(ChannelBuffer & mH)
    {
        return asyncRecv(mH).get();
    }

    bool BtChannel::opened()
    {
        return mSendSocketSet  && mRecvSocketSet;
    }
    void BtChannel::waitForOpen()
    {
        return mOpenFut.get();
    }

    void BtChannel::close()
    {
        // indicate that no more messages should be queued and to fulfill
        // the mSocket->mDone* promised.
        mStopped = true;


        BtIOOperation closeRecv;
        closeRecv.mType = BtIOOperation::Type::CloseRecv;
        std::promise<u64> recvPromise;
        closeRecv.mPromise = &recvPromise;

        mEndpoint.getIOService().dispatch(this, closeRecv);

        BtIOOperation closeSend;
        closeSend.mType = BtIOOperation::Type::CloseSend;
        std::promise<u64> sendPromise;
        closeSend.mPromise = &sendPromise;
        mEndpoint.getIOService().dispatch(this, closeSend);

        recvPromise.get_future().get();
        sendPromise.get_future().get();

        // ok, the send and recv queues are empty. Lets close the socket
        mHandle->close();

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
        mTotalSentData = 0;
        mMaxOutstandingSendData = 0;
        mOutstandingSendData = 0;
    }

    u64 BtChannel::getTotalDataSent() const
    {
        return (u64)mTotalSentData;
    }

    u64 BtChannel::getMaxOutstandingSendData() const
    {
        return (u64)mMaxOutstandingSendData;
    }
}
