#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/ArrayView.h>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Network/IoBuffer.h>
#include <cryptoTools/Network/Endpoint.h>
#include <future>
#define CHANNEL_LOGGING

namespace osuCrypto {





    class Socket;
    class Endpoint;
    class Endpoint;
    class ChannelBase;
    class SocketInterface;
    class BoostSocketInterface;

    class Channel
    {
        friend class IOService;
        friend class Endpoint;
        Channel(Endpoint& endpoint, std::string localName, std::string remoteName);
    public:
        Channel(IOService& ios, SocketInterface* sock);
        Channel(Channel && move) = default;
        Channel(const Channel & copy) = default;
        Channel() = default;

        ~Channel();

        Channel& operator=(Channel&& move);
        Channel& operator=(const Channel& copy);

        /// <summary>Get the local endpoint for this channel.</summary>
        Endpoint& getEndpoint();

        /// <summary>The handle for this channel. Both ends will always have the same name.</summary>
        std::string getName() const;

        /// <summary>Returns the name of the remote endpoint.</summary>
        std::string getRemoteName() const;

        /// <summary>Sets the data send and recieved counters to zero.</summary>
        void resetStats();

        /// <summary>Returns the amount of data that this channel has sent since it was created or when resetStats() was last called.</summary>
        u64 getTotalDataSent() const;

        /// <summary>Returns the amount of data that this channel has sent since it was created or when resetStats() was last called.</summary>
        u64 getTotalDataRecv() const;

        /// <summary>Returns the maximum amount of data that this channel has queued up to send since it was created or when resetStats() was last called.</summary>
        u64 getMaxOutstandingSendData() const;

        /// <summary>length bytes starting at data will be sent over the network asynchronously. WARNING: data lifetime must be handled by caller.</summary>
        void asyncSend(const void * data, u64 length);

        /// <summary>Data will be sent over the network asynchronously. WARNING: data lifetime must be handled by caller.</summary>
        void asyncSend(const void * bufferPtr, u64 length, std::function<void()> callback);

        /// <summary>buffer will be MOVED and then sent over the network asynchronously.
        /// Note: The type within the unique_ptr must be a container type, see is_container for requirements.
        /// Returns: void </summary>
        template <class Container>
        typename std::enable_if_t<is_container<Container>::value, void>
            asyncSend(std::unique_ptr<Container> buffer);

        /// <summary>buffer will be MOVED and then sent over the network asynchronously.
        /// Note: The type within the unique_ptr must be a container type, see is_container for requirements.
        /// Returns: void </summary>
        template <class Container>
        typename std::enable_if_t<is_container<Container>::value, void>
            asyncSend(std::shared_ptr<Container> buffer);


        /// <summary>Container c will be MOVED and then sent over the network asynchronously.
        /// Note: The type of Container must be a container type, see is_container for requirements.
        /// Returns: void </summary>
        template <class Container>
        typename std::enable_if_t<is_container<Container>::value, void>
            asyncSend(Container&& c);

        /// <summary>Performs a data copy and then sends the result over the network asynchronously.
        /// Note: The type of Container must be a container type, see is_container for requirements.
        /// Returns: void </summary>
        template <typename  Container>
        typename std::enable_if_t<is_container<Container>::value, void>
            asyncSendCopy(const Container& buf);

        /// <summary>Performs a data copy and then sends the result over the network asynchronously. </summary>
        void asyncSendCopy(const void * bufferPtr, u64 length);

        /// <summary>Synchronous call to send length bytes starting at data over the network. </summary>
        void send(const void * bufferPtr, u64 length);

        /// <summary> Synchronous call to send the data in Container over the network.
        /// Note: The type of Container must be a container type, see is_container for requirements.
        /// Returns: void  </summary>
        template <class Container>
        typename std::enable_if_t<is_container<Container>::value, void>
            send(const Container& buf);

        /// <summary>Asynchronous call to recv length bytes of data over the network. The data will be written at dest.
        /// WARNING: return value will through if received message length does not match. </summary>
        std::future<u64> asyncRecv(void* dest, u64 length, std::function<void()> fn);


        /// <summary>Asynchronous call to recv length bytes of data over the network. The data will be written at dest.
        /// WARNING: return value will through if received message length does not match. </summary>
        std::future<u64> asyncRecv(void* dest, u64 length);

        /// <summary>Asynchronous call to receive data over the network.
        /// Note: Conatiner can be resizable. If received size does not match Container::size(),
        ///       Container::resize(Container::size_type newSize) will be called if avaliable.
        /// Returns: a void future that is fulfilled when all of the data has been written. </summary>
        template <class Container>
        typename std::enable_if_t<
            is_container<Container>::value &&
            !has_resize<Container, void(typename Container::size_type)>::value, std::future<u64>>
            asyncRecv(Container& c);


        /// <summary>Asynchronous call to receive data over the network.
        /// Note: Conatiner can be resizable. If received size does not match Container::size(),
        ///       Container::resize(Container::size_type newSize) will be called if avaliable.
        /// Returns: a void future that is fulfilled when all of the data has been written. </summary>
        template <class Container>
        typename std::enable_if_t<
            is_container<Container>::value &&
            has_resize<Container, void(typename Container::size_type)>::value, std::future<u64>>
            asyncRecv(Container& c);

        template <class Container>
        typename std::enable_if_t<
            is_container<Container>::value &&
            has_resize<Container, void(typename Container::size_type)>::value, void>
            recv(Container & c)
        {
            asyncRecv(c).get();
        }


        template <class Container>
        typename std::enable_if_t< 
            is_container<Container>::value &&
            !has_resize<Container, void(typename Container::size_type)>::value, void>
            recv(Container & c)
        {
            asyncRecv(c).get();
        }

        /// <summary>Synchronous call to receive data over the network.
        /// WARNING: will through if received message length does not match.</summary>
        void recv(void * dest, u64 length);

        /// <summary>Returns whether this channel is open in that it can send/receive data</summary>
        bool isConnected();

        /// <summary>A blocking call that waits until the channel is open in that it can send/receive data</summary>
        void waitForConnection();

        /// <summary>Close this channel to denote that no more data will be sent or received.</summary>
        void close();


        enum class Status
        {
            Normal,
            RecvSizeError,
            FatalError,
            Stopped
        };


        std::shared_ptr<ChannelBase> mBase;

    private:



        void dispatch(std::unique_ptr<IOOperation> op);




        //inline void errorCheck()
        //{
        //    //if (mStopped) throw std::runtime_error("Channel has been stopped\n");
        //    //if (mStatus) throw std::runtime_error("Channel is in error state\n  Reason: " + mErrorMessage);
        //}

    };


    inline std::ostream& operator<< (std::ostream& o,const Channel::Status& s)
    {
        switch (s)
        {
        case Channel::Status::Normal:
            o << "Status::Normal";
            break;
        case Channel::Status::RecvSizeError:
            o << "Status::RecvSizeError";
            break;
        case Channel::Status::FatalError:
            o << "Status::FatalError";
            break;
        case Channel::Status::Stopped:
            o << "Status::Stopped";
            break;
        default:
            break;
        }
        return o;
    }

#ifdef CHANNEL_LOGGING
    class ChannelLog
    {
    public:
        std::vector<std::string> mMessages;
        std::mutex mLock;

        void push(const std::string& msg)
        {
            mLock.lock();
            mMessages.emplace_back(msg);
            mLock.unlock();
        }


    };
#endif

    class ChannelBase
    {
    public:
        ChannelBase(Endpoint& endpoint, std::string localName, std::string remoteName);
        ChannelBase(IOService& ios, SocketInterface* sock);
        ~ChannelBase()
        {
            close();
        }

        IOService& mIos;
        Endpoint* mEndpoint;
        std::string mRemoteName, mLocalName;
        u64 mId;

        u32 mRecvSizeBuff, mSendSizeBuff;

        Channel::Status mRecvStatus, mSendStatus;
        std::unique_ptr<SocketInterface> mHandle;



        boost::asio::strand mSendStrand, mRecvStrand;

        std::deque<std::unique_ptr<IOOperation>> mSendQueue, mRecvQueue;
        std::promise<void> mOpenProm;
        std::shared_future<void> mOpenFut;

        std::atomic<u8> mOpenCount;
        bool mRecvSocketSet, mSendSocketSet;

        std::string mRecvErrorMessage, mSendErrorMessage;
        u64 mOutstandingSendData, mMaxOutstandingSendData, mTotalSentData, mTotalRecvData;

        std::promise<u64> mSendQueueEmptyProm, mRecvQueueEmptyProm;
        std::future<u64> mSendQueueEmptyFuture, mRecvQueueEmptyFuture;


        void setRecvFatalError(std::string reason);
        void setSendFatalError(std::string reason);

        void setBadRecvErrorState(std::string reason);
        void clearBadRecvErrorState();

        void cancelRecvQueuedOperations();
        void cancelSendQueuedOperations();

        void close();
        IOService& getIOService() { return mIos; }

        bool stopped() { return mSendStatus == Channel::Status::Stopped; }

#ifdef CHANNEL_LOGGING
        std::atomic<u32> mOpIdx;
        ChannelLog mLog;
#endif

    };

    template<class Container>
    typename std::enable_if_t<is_container<Container>::value, void> Channel::asyncSend(std::unique_ptr<Container> c)
    {
        // not zero and less that 32 bits
        Expects(channelBuffSize(*c) - 1 < u32(-2) && mBase->mSendStatus == Status::Normal);

        auto op = std::unique_ptr<IOOperation>(new MoveChannelBuff<std::unique_ptr<Container>>(std::move(c)));

        dispatch(std::move(op));
    }

    template<class Container>
    typename std::enable_if_t<is_container<Container>::value, void> Channel::asyncSend(std::shared_ptr<Container> c)
    {
        // not zero and less that 32 bits
        Expects(channelBuffSize(*c) - 1 < u32(-2) && mBase->mSendStatus == Status::Normal);

        auto op = std::unique_ptr<IOOperation>(new MoveChannelBuff<std::shared_ptr<Container>>(std::move(c)));

        dispatch(std::move(op));
    }


    template<class Container>
    typename std::enable_if_t<is_container<Container>::value, void> Channel::asyncSend(Container && c)
    {
        // not zero and less that 32 bits
        Expects(channelBuffSize(c) - 1 < u32(-2)  && mBase->mSendStatus == Status::Normal);

        auto op = std::unique_ptr<IOOperation>(new MoveChannelBuff<Container>(std::move(c)));

        dispatch(std::move(op));
    }

    template <class Container>
    typename std::enable_if_t<
        is_container<Container>::value &&
        !has_resize<Container, void(typename Container::size_type)>::value, std::future<u64>>
        Channel::asyncRecv(Container & c)
    {
        // not zero and less that 32 bits
        Expects(channelBuffSize(c) - 1 < u32(-2) && mBase->mRecvStatus == Status::Normal);

        auto op = std::unique_ptr<IOOperation>(new ChannelBuffRef<Container>(c, IOOperation::Type::RecvData));
        auto future = op->mPromise.get_future();

        dispatch(std::move(op));

        return future;
    }



    template <class Container>
    typename std::enable_if_t<
        is_container<Container>::value &&
        has_resize<Container, void(typename Container::size_type)>::value, std::future<u64>>
        Channel::asyncRecv(Container & c)
    {
        // not zero and less that 32 bits
        Expects(mBase->mRecvStatus == Status::Normal);

        auto op = std::unique_ptr<IOOperation>(new ResizableChannelBuffRef<Container>(c));

        auto future = op->mPromise.get_future();
        dispatch(std::move(op));
        return future;
    }

    template<class Container>
    typename std::enable_if_t<is_container<Container>::value, void> Channel::send(const Container & buf)
    {
        send(channelBuffData(buf), channelBuffSize(buf));
    }        

    template<typename Container>
    typename std::enable_if_t<is_container<Container>::value, void> Channel::asyncSendCopy(const Container & buf)
    {
        asyncSend(std::move(Container(buf)));
    }
}
