#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/IoBuffer.h>
#include <cryptoTools/Network/SocketAdapter.h>

#include <future>
#include <ostream>
#include <deque>

//#define CHANNEL_LOGGING

namespace osuCrypto {

    class ChannelBase;
	class Session;
	class IOService;
	class SocketInterface;

	// Channel is the standard interface use to send data over the network.
	// See frontend_cryptoTools/Tutorial/Network.cpp for examples.
    class Channel
    {
    public:

		// The default constructors
        Channel() = default;
        Channel(const Channel & copy) = default;
        Channel(Channel && move) = default;

		// Special constructor used to construct a Channel from some socket.
        Channel(IOService& ios, SocketInterface* sock);
        ~Channel();

		// Default assignment
        Channel& operator=(Channel&& move);

		// Default assignment
		Channel& operator=(const Channel& copy);




		//////////////////////////////////////////////////////////////////////////////
		//						   Sending interface								//
		//////////////////////////////////////////////////////////////////////////////

		// Sends length number of T pointed to by src over the network. The type T 
		// must be POD. Returns once all the data has been sent.
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, void>
			send(const T* src, u64 length);

		// Sends the data in buf over the network. The type Container  must meet the 
		// requirements defined in IoBuffer.h. Returns once all the data has been sent.
		template <class T>
		typename std::enable_if_t<std::is_pod<T>::value, void>
			send(const T& buf);

		// Sends the data in buf over the network. The type Container  must meet the 
		// requirements defined in IoBuffer.h. Returns once all the data has been sent.
		template <class Container>
		typename std::enable_if_t<is_container<Container>::value, void>
			send(const Container& buf);




		// Sends the data in buf over the network. The type T must be POD.
		// Returns before the data has been sent. The life time of the data must be 
		// managed externally to ensure it lives longer than the async operations.
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, void>
			asyncSend(const T* data, u64 length);

		// Sends the data in buf over the network. The type Container  must meet the 
		// requirements defined in IoBuffer.h. Returns before the data has been sent. 
		// The life time of the data must be managed externally to ensure it lives 
		// longer than the async operations.  callback is a function that is called 
		// from another thread once the send operation has completed.
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, void>
			asyncSend(const T * bufferPtr, u64 length, std::function<void()> callback);

		// Sends the data in buf over the network. The type T must be POD.
		// Returns before the data has been sent. The life time of the data must be 
		// managed externally to ensure it lives longer than the async operations.
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, void>
			asyncSend(const T& data);

		// Sends the data in buf over the network. The type T must be POD.
		// Returns before the data has been sent. The life time of the data must be 
		// managed externally to ensure it lives longer than the async operations.
		template<typename Container>
		typename std::enable_if_t<is_container<Container>::value, void>
			asyncSend(const Container& data);

		// Sends the data in buf over the network. The type Container  must meet the 
		// requirements defined in IoBuffer.h. Returns before the data has been sent. 
        template <class Container>
        typename std::enable_if_t<is_container<Container>::value, void>
            asyncSend(Container&& c);

		// Sends the data in buf over the network. The type Container  must meet the 
		// requirements defined in IoBuffer.h. Returns before the data has been sent. 
		template <class Container>
		typename std::enable_if_t<is_container<Container>::value, void>
			asyncSend(std::unique_ptr<Container> buffer);

		// Sends the data in buf over the network. The type Container  must meet the 
		// requirements defined in IoBuffer.h. Returns before the data has been sent. 
		template <class Container>
		typename std::enable_if_t<is_container<Container>::value, void>
			asyncSend(std::shared_ptr<Container> buffer);




		// Performs a data copy and then sends the data in buf over the network. 
		//  The type T must be POD. Returns before the data has been sent. 
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, void>
			asyncSendCopy(const T & buff);

		// Performs a data copy and then sends the data in buf over the network. 
		//  The type T must be POD. Returns before the data has been sent. 
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, void>
			asyncSendCopy(const T * bufferPtr, u64 length);

        // Performs a data copy and then sends the data in buf over the network. 
		// The type Container must meet the requirements defined in IoBuffer.h. 
		// Returns before the data has been sent. 
        template <typename  Container>
        typename std::enable_if_t<is_container<Container>::value, void>
            asyncSendCopy(const Container& buf);


		//////////////////////////////////////////////////////////////////////////////
		//						   Receiving interface								//
		//////////////////////////////////////////////////////////////////////////////

		// Receive data over the network. If possible, the container c will be resized
		// to fit the data. The function returns once all the data has been received.
		template <class Container>
		typename std::enable_if_t<
			is_container<Container>::value &&
			has_resize<Container, void(typename Container::size_type)>::value, void>
			recv(Container & c)
		{ asyncRecv(c).get(); }

		// Receive data over the network. The container c must be the correct size to 
		// fit the data. The function returns once all the data has been received.
		template <class Container>
		typename std::enable_if_t<
			is_container<Container>::value &&
			!has_resize<Container, void(typename Container::size_type)>::value, void>
			recv(Container & c)
		{ asyncRecv(c).get(); }

		// Receive data over the network. The function returns once all the data 
		// has been received.
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, void>
			recv(T * dest, u64 length);

		// Receive data over the network. The function returns once all the data 
		// has been received.
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, void>
			recv(T & dest) { recv(&dest, 1); }

		// Receive data over the network asynchronously. The function returns right away,
		// before the data has been received. When all the data has benn received the 
		// future is set.
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, std::future<void>>
			asyncRecv(T* dest, u64 length);

		// Receive data over the network asynchronously. The function returns right away,
		// before the data has been received. When all the data has benn received the 
		// future is set and the callback fn is called.
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, std::future<void>>
			asyncRecv(T* dest, u64 length, std::function<void()> fn);

		// Receive data over the network asynchronously. The function returns right away,
		// before the data has been received. When all the data has benn received the 
		// future is set.
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value, std::future<void>>
			asyncRecv(T& dest) { return asyncRecv(&dest, 1); }

		// Receive data over the network asynchronously. The function returns right away,
		// before the data has been received. When all the data has benn received the 
		// future is set. The container must be the correct size to fit the data received.
        template <class Container>
        typename std::enable_if_t<
            is_container<Container>::value &&
            !has_resize<Container, void(typename Container::size_type)>::value, std::future<void>>
            asyncRecv(Container& c);

		// Receive data over the network asynchronously. The function returns right away,
		// before the data has been received. When all the data has benn received the 
		// future is set. The container is resized to fit the data.
        template <class Container>
        typename std::enable_if_t<
            is_container<Container>::value &&
            has_resize<Container, void(typename Container::size_type)>::value, std::future<void>>
            asyncRecv(Container& c);

		// Receive data over the network asynchronously. The function returns right away,
		// before the data has been received. When all the data has benn received the 
		// future is set and the callback fn is called. The container must be the correct 
		// size to fit the data received.
		template <class Container>
		typename std::enable_if_t<
			is_container<Container>::value &&
			has_resize<Container, void(typename Container::size_type)>::value, std::future<void>>
			asyncRecv(Container& c, std::function<void()> fn);


		//////////////////////////////////////////////////////////////////////////////
		//						   Utility functions								//
		//////////////////////////////////////////////////////////////////////////////

		// Get the local endpoint for this channel.
		//Session& getSession();

		// The handle for this channel. Both ends will always have the same name.
		std::string getName() const;

		// Returns the name of the remote endpoint.
		std::string getRemoteName() const;

		// Return the name of the endpoint of this channel has once.
		Session getSession() const;

		// Sets the data send and recieved counters to zero.
		void resetStats();

		// Returns the amount of data that this channel has sent since it was created or when resetStats() was last called.
		u64 getTotalDataSent() const;

		// Returns the amount of data that this channel has sent since it was created or when resetStats() was last called.
		u64 getTotalDataRecv() const;

		// Returns the maximum amount of data that this channel has queued up to send since it was created or when resetStats() was last called.
		u64 getMaxOutstandingSendData() const;

        // Returns whether this channel is open in that it can send/receive data
        bool isConnected();

        // A blocking call that waits until the channel is open in that it can send/receive data
		// Returns if the connection has been made. Always true if no timeout is provided.
        bool waitForConnection(std::chrono::milliseconds timeout);

		// A blocking call that waits until the channel is open in that it can send/receive data
		// Returns if the connection has been made. 
		void waitForConnection();

        // Close this channel to denote that no more data will be sent or received.
		// blocks until all pending operations have completed.
        void close();

		// Aborts all current operations (connect, send, receive).
		void cancel();

        enum class Status { Normal, /*RecvSizeError, FatalError,*/ Stopped };

        std::shared_ptr<ChannelBase> mBase;

    private:
        void dispatch(std::unique_ptr<IOOperation> op);

		friend class IOService;
		friend class Session;
		Channel(Session& endpoint, std::string localName, std::string remoteName);
    };


    inline std::ostream& operator<< (std::ostream& o,const Channel::Status& s)
    {
        switch (s)
        {
        case Channel::Status::Normal:
            o << "Status::Normal";
            break;
        //case Channel::Status::RecvSizeError:
        //    o << "Status::RecvSizeError";
        //    break;
        //case Channel::Status::FatalError:
        //    o << "Status::FatalError";
        //    break;
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

	class SocketConnectError : public std::runtime_error
	{
	public:
		SocketConnectError(const std::string& reason)
			:std::runtime_error(reason)
		{}
	};

	struct SessionBase;

	// The Channel base class the actually holds a socket. 
    class ChannelBase
    {
    public:
        ChannelBase(Session& endpoint, std::string localName, std::string remoteName);
        ChannelBase(IOService& ios, SocketInterface* sock);
        ~ChannelBase()
        {
            close();
        }

        IOService& mIos;
		std::unique_ptr<boost::asio::io_service::work> mWork;

		std::shared_ptr<SessionBase> mSession;
        std::string mRemoteName, mLocalName;

        u32 mRecvSizeBuff, mSendSizeBuff;

        Channel::Status mRecvStatus, mSendStatus;
        std::unique_ptr<SocketInterface> mHandle;
		boost::asio::deadline_timer mTimer;

        boost::asio::strand mSendStrand, mRecvStrand;

        std::deque<std::unique_ptr<IOOperation>> mSendQueue, mRecvQueue;
        std::promise<void> mOpenProm;
        std::shared_future<void> mOpenFut;

        std::atomic<u8> mOpenCount;
        bool mRecvSocketSet, mSendSocketSet;

        std::string mRecvErrorMessage, mSendErrorMessage;
        u64 mOutstandingSendData, mMaxOutstandingSendData, mTotalSentData, mTotalRecvData;


		bool mRecvQueueEmpty = false, mSendQueueEmpty = false;
        std::promise<void> mSendQueueEmptyProm, mRecvQueueEmptyProm;
        std::future<void> mSendQueueEmptyFuture, mRecvQueueEmptyFuture;


		void asyncConnectToServer(const boost::asio::ip::tcp::endpoint&address);
		std::function<void(const boost::system::error_code&)> mConnectCallback;
		
        void setRecvFatalError(std::string reason);
        void setSendFatalError(std::string reason);

        void setBadRecvErrorState(std::string reason);
        void clearBadRecvErrorState();

        void cancelRecvQueuedOperations();
        void cancelSendQueuedOperations();

		void close();
		void cancel();
        IOService& getIOService() { return mIos; }

        bool stopped() { return mSendStatus == Channel::Status::Stopped && mRecvStatus == Channel::Status::Stopped; }


		bool mActiveRecvSizeError = false;
		bool activeRecvSizeError() const { return mActiveRecvSizeError; }
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
	typename std::enable_if_t<is_container<Container>::value, void> Channel::asyncSend(const Container & c)
	{
		// not zero and less that 32 bits
		Expects(channelBuffSize(c) - 1 < u32(-2) && mBase->mSendStatus == Status::Normal);

		auto* buff = c.data();
		auto size = c.size() * sizeof(typename Container::value_type);

		auto op = std::unique_ptr<IOOperation>(new PointerSizeBuff(buff, size, IOOperation::Type::SendData));

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
        !has_resize<Container, void(typename Container::size_type)>::value, std::future<void>>
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
        has_resize<Container, void(typename Container::size_type)>::value, std::future<void>>
        Channel::asyncRecv(Container & c)
    {
        // not zero and less that 32 bits
        Expects(mBase->mRecvStatus == Status::Normal);

        auto op = std::unique_ptr<IOOperation>(new ResizableChannelBuffRef<Container>(c));

        auto future = op->mPromise.get_future();
        dispatch(std::move(op));
        return future;
    }


	template <class Container>
	typename std::enable_if_t<
		is_container<Container>::value &&
		has_resize<Container, void(typename Container::size_type)>::value, std::future<void>>
		Channel::asyncRecv(Container & c, std::function<void()> fn)
	{
		// not zero and less that 32 bits
		Expects(mBase->mRecvStatus == Status::Normal);

		auto op = std::unique_ptr<IOOperation>(new ResizableChannelBuffRef<Container>(c));
		op->mCallback = std::move(fn);

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


	template<typename T>
	typename std::enable_if_t<std::is_pod<T>::value, void>
		Channel::send(const T* buffT, u64 sizeT)
	{
		u8* buff = (u8*)buffT;
		auto size = sizeT * sizeof(T);

		// not zero and less that 32 bits
		Expects(size - 1 < u32(-2) && mBase->mSendStatus == Status::Normal);

		auto op = std::unique_ptr<IOOperation>(new PointerSizeBuff(buff, size, IOOperation::Type::SendData));
		auto future = op->mPromise.get_future();
		dispatch(std::move(op));
		future.get();
	}

	template<typename T>
	typename std::enable_if_t<std::is_pod<T>::value, void>
		Channel::send(const T& buffT)
	{
		send(&buffT, 1);
	}

	template<typename T>
	typename std::enable_if_t<std::is_pod<T>::value, std::future<void>>
		Channel::asyncRecv(T* buffT, u64 sizeT)
	{
		u8* buff = (u8*)buffT;
		auto size = sizeT * sizeof(T);

		// not zero and less that 32 bits
		Expects(size - 1 < u32(-2) && mBase->mRecvStatus == Status::Normal);

		auto op = std::unique_ptr<IOOperation>(new PointerSizeBuff(buff, size, IOOperation::Type::RecvData));
		auto future = op->mPromise.get_future();
		dispatch(std::move(op));
		return future;
	}
	
	template<typename T>
	typename std::enable_if_t<std::is_pod<T>::value, std::future<void>>
		Channel::asyncRecv(T * buffT, u64 sizeT, std::function<void()> fn)
	{
		u8* buff = (u8*)buffT;
		auto size = sizeT * sizeof(T);

		// not zero and less that 32 bits
		Expects(size - 1 < u32(-2) && mBase->mRecvStatus == Status::Normal);

		auto op = std::unique_ptr<IOOperation>(new PointerSizeBuff(buff, size, IOOperation::Type::RecvData));
		op->mCallback = std::move(fn);
		auto future = op->mPromise.get_future();
		dispatch(std::move(op));
		return future;
	}

	template<typename T>
	typename std::enable_if_t<std::is_pod<T>::value, void>
		Channel::asyncSend(const T * buffT, u64 sizeT)
	{
		u8* buff = (u8*)buffT;
		auto size = sizeT * sizeof(T);

		// not zero and less that 32 bits
		Expects(size - 1 < u32(-2) && mBase->mSendStatus == Status::Normal);

		auto op = std::unique_ptr<IOOperation>(new PointerSizeBuff(buff, size, IOOperation::Type::SendData));
		dispatch(std::move(op));
	}



	template<typename T>
	typename std::enable_if_t<std::is_pod<T>::value, void>
		Channel::asyncSend(const T &v)
	{
		asyncSend(&v, 1);
	}


	template<typename T>
	typename std::enable_if_t<std::is_pod<T>::value, void>
		Channel::asyncSend(const T * buff, u64 size, std::function<void()> callback)
	{
		// not zero and less that 32 bits
		Expects(size - 1 < u32(-2) && mBase->mSendStatus == Status::Normal);

		auto op = std::unique_ptr<IOOperation>(new PointerSizeBuff(buff, size, IOOperation::Type::SendData));
		op->mCallback = callback;

		dispatch(std::move(op));
	}


	template<typename T>
	typename std::enable_if_t<std::is_pod<T>::value, void>
		Channel::recv(T* buffT, u64 sizeT)
	{
		u8* buff = (u8*)buffT;
		auto size = sizeT * sizeof(T);

		try {
			// schedule the recv.
			auto request = asyncRecv(buff, size);

			// block until the receive has been completed.
			// Could throw if the length is wrong.
			request.get();
		}
		catch (BadReceiveBufferSize& bad)
		{
			std::cout << bad.what() << std::endl;
			throw;
		}
	}

	template<typename T>
	typename std::enable_if_t<std::is_pod<T>::value, void>
		Channel::asyncSendCopy(const T* bufferPtr, u64 length)
	{
		std::vector<u8> bs((u8*)bufferPtr, (u8*)bufferPtr + length * sizeof(T));
		asyncSend(std::move(bs));
	}


	template<typename T>
	typename std::enable_if_t<std::is_pod<T>::value, void>
		Channel::asyncSendCopy(const T& buf)
	{
		asyncSendCopy(&buf, 1);
	}
}
