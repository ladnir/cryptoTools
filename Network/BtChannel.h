#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 

#include "boost/asio.hpp"
#include <deque>
#include "cryptoTools/Common/Defines.h"


#include "cryptoTools/Network/Channel.h"
#include <future>

namespace osuCrypto {


    struct BtIOOperation
    {
        enum class Type
        {
            RecvName,
            RecvData,
            CloseRecv,
            SendData,
            CloseSend,
            CloseThread
        };

        BtIOOperation()
        {
            //clear();
            mType = (Type)0;
            mSize = 0;
            mBuffs[0] = boost::asio::buffer(&mSize, sizeof(u32));
            mBuffs[1] = boost::asio::mutable_buffer();
            mOther = nullptr;
            mPromise = nullptr;
            //mCallback = std::function<void()>();
        }

        BtIOOperation(const BtIOOperation& copy)
        {
            mType = copy.mType;
            mSize = copy.mSize;
            mBuffs[0] = boost::asio::buffer(&mSize, sizeof(u32));
            mBuffs[1] = copy.mBuffs[1];
            mOther = copy.mOther;
            mCallback = copy.mCallback;
            mPromise = copy.mPromise;
        }

        //void clear()
        //{
        //    mType = (Type)0;
        //    mSize = 0;
        //    mBuffs[0] = boost::asio::buffer(&mSize, sizeof(u32));
        //    mBuffs[1] = boost::asio::mutable_buffer();
        //    mOther = nullptr;
        //    mPromise = nullptr;
        //    mCallback = std::function<void()>();
        //}


        std::array<boost::asio::mutable_buffer, 2> mBuffs;
        Type mType;
        u32 mSize;
        std::function<void()> mCallback;
        void* mOther;
        std::promise<u64>* mPromise;
        std::exception_ptr mException;
        //std::function<void()> mCallback;
    };


    //class BtSocket;
    class BtEndpoint;

    class BtChannel : public  Channel
    {

    public:

        BtChannel(BtEndpoint& endpoint,std::string localName, std::string remoteName);

        ~BtChannel();

        /// <summary>Get the local endpoint for this channel.</summary>
        Endpoint& getEndpoint()  override;

        /// <summary>The handle for this channel. Both ends will always have the same name.</summary>
        std::string getName() const override;

        /// <summary>Returns the name of the remote endpoint.</summary>
        std::string getRemoteName() const;

        void resetStats() override;

        u64 getTotalDataSent() const override;

        u64 getMaxOutstandingSendData() const override;
        
        /// <summary>Data will be sent over the network asynchronously. WARNING: data lifetime must be handled by caller.</summary>
        void asyncSend(const void * bufferPtr, u64 length) override;

        /// <summary>Buffer will be MOVED and then sent over the network asynchronously. </summary>
        void asyncSend(std::unique_ptr<ChannelBuffer> mH) override;

        /// <summary>Data will be sent over the network asynchronously. WARNING: data lifetime must be handled by caller.</summary>
        void asyncSend(const void * bufferPtr, u64 length, std::function<void(void)> callback) override;

        /// <summary>Synchronous call to send data over the network. </summary>
        void send(const void * bufferPtr, u64 length) override;



        std::future<u64> asyncRecv(void* dest, u64 length) override;
        std::future<u64> asyncRecv(ChannelBuffer& mH) override;

        /// <summary>Synchronous call to receive data over the network. Assumes dest has byte size length. WARNING: will through if received message length does not match.</summary>
        u64 recv(void* dest, u64 length) override;

        /// <summary>Synchronous call to receive data over the network. Will resize buffer to be the appropriate size.</summary>
        u64 recv(ChannelBuffer& mH) override;

        /// <summary>Returns whether this channel is open in that it can send/receive data</summary>
        bool opened() override;

        /// <summary>A blocking call that waits until the channel is open in that it can send/receive data</summary>
        void waitForOpen() override;

        /// <summary>Close this channel to denote that no more data will be sent or received.</summary>
        void close() override;


        boost::asio::ip::tcp::socket* mHandle;
        boost::asio::strand mSendStrand, mRecvStrand;

        std::deque<BtIOOperation> mSendQueue, mRecvQueue;
        std::promise<void> mOpenProm;
        std::shared_future<void> mOpenFut;

        std::atomic<u8> mOpenCount;
        bool mStopped, mRecvSocketSet, mSendSocketSet;
        u64 mId;
        std::atomic<u64> mOutstandingSendData, mMaxOutstandingSendData, mTotalSentData;

        //BtSocket mSocket;
        BtEndpoint& mEndpoint;
        std::string mRemoteName, mLocalName;
    };

}
