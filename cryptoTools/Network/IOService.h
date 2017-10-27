#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Network/Session.h>

# if defined(_WINSOCKAPI_) && !defined(_WINSOCK2API_)
#  error WinSock.h has already been included. Please move the boost headers above the WinNet*.h headers
# endif // defined(_WINSOCKAPI_) && !defined(_WINSOCK2API_)

#ifndef _MSC_VER
#pragma GCC diagnostic push 
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#include <boost/asio.hpp>
#ifndef _MSC_VER
#pragma GCC diagnostic pop
#endif

#include <thread> 
#include <mutex>
#include <list> 
#include <future>
#include <string>
#include <unordered_map>
#include <functional>
//#include <optional>

namespace osuCrypto
{

	class Acceptor;
	class IOOperation;

    std::vector<std::string> split(const std::string &s, char delim);

    class IOService
    {
        friend class Channel;
        friend class Session;

    public:

        IOService(const IOService&) = delete;

        // Constructor for the IO service that services network IO operations.
        // threadCount is The number of threads that should be used to service IO operations. 0 = use # of CPU cores.
        IOService(u64 threadCount = 0);
        ~IOService();

        boost::asio::io_service mIoService;
		boost::asio::strand mStrand;

        std::unique_ptr<boost::asio::io_service::work> mWorker;

        std::list<std::thread> mWorkerThrds;

        // The list of acceptor objects that hold state about the ports that are being listened to. 
        std::list<Acceptor> mAcceptors;

        void printErrorMessages(bool v);

        // indicates whether stop() has been called already.
		bool mStopped = false;

        // The mutex the protects sensitive objects in this class. 
        //std::mutex mMtx;

        void receiveOne(ChannelBase* socket);

        void sendOne(ChannelBase* socket);

        void startSocket(ChannelBase* chl, std::unique_ptr<BoostSocketInterface> socket);

        // Used to queue up asynchronous socket operations.
        void dispatch(ChannelBase* socket, std::unique_ptr<IOOperation> op);

        // Gives a new endpoint which is a host endpoint the acceptor which provides sockets. 
        void aquireAcceptor(std::shared_ptr<SessionBase>& session);

        // Shut down the IO service. WARNING: blocks until all Channels and Sessions are stopped.
        void stop();

        bool mPrint = false;
    };


	namespace details
	{
		struct NamedSocket {
			NamedSocket() = default;
			NamedSocket(NamedSocket&&) = default;

			std::string mLocalName, mRemoteName;
			std::unique_ptr<BoostSocketInterface> mSocket;
		};

		struct SocketGroup
		{
			SocketGroup() = default;
			SocketGroup(SocketGroup&&) = default;

			bool hasMatchingSocket(const std::shared_ptr<ChannelBase>& chl) const;

			std::function<void()> removeMapping;


			std::string mName;
			u64 mSessionID = 0;
			std::list<NamedSocket> mSockets;
		};

		struct SessionGroup
		{
			SessionGroup() = default;

			bool hasSubscriptions() const {
				return mChannels.size() || mBase.expired() == false;
			}

			void add(NamedSocket sock, Acceptor* a);
			void add(const std::shared_ptr<ChannelBase>& chl, Acceptor* a);

			bool hasMatchingChannel(const NamedSocket& sock) const;

			void merge(SocketGroup& merge, Acceptor* a);

			std::weak_ptr<SessionBase> mBase;
			std::function<void()> removeMapping;

			std::list<NamedSocket> mSockets;
			std::list<std::shared_ptr<ChannelBase>> mChannels;
		};
	}

	class Acceptor
	{

	public:
		Acceptor() = delete;
		Acceptor(const Acceptor&) = delete;

		Acceptor(IOService& ioService);
		~Acceptor();

		std::promise<void> mPendingSocketsEmptyProm, mStoppedPromise;
		std::future<void> mPendingSocketsEmptyFuture, mStoppedFuture;

		IOService& mIOService;

		boost::asio::strand mStrand;
		boost::asio::ip::tcp::acceptor mHandle;

		std::atomic<bool> mStopped;
		//std::mutex mSocketChannelPairsMtx;
		bool mListening = false;

		struct PendingSocket {
			PendingSocket(boost::asio::io_service& ios) : mSock(ios) {}
			boost::asio::ip::tcp::socket mSock;
			std::string mBuff;
		};

		std::list<PendingSocket> mPendingSockets;
		
		typedef std::list<details::SessionGroup> GroupList;
		typedef std::list<details::SocketGroup> SocketGroupList;


		SocketGroupList mSockets;
		// A list of local sessions that have not been paired up with sockets. The key is the session
		// name. For any given session name, there my be several sessions.
		std::unordered_map<std::string, std::list<SocketGroupList::iterator>> mUnclaimedSockets;

		GroupList mGroups;
		// A list of local sessions that have not been paired up with sockets. The key is the session
		// name. For any given session name, there my be several sessions.
		std::unordered_map<std::string, std::list<GroupList::iterator>> mUnclaimedGroups;
		std::unordered_map<std::string, GroupList::iterator> mClaimedGroups;

		// A list of local sessons. The key is the session name and the session ID. 
		//std::unordered_map<std::pair<std::string,u64>, SessionGroup> mGroups;

		// A map of endpoint groups which have well defined name.
		// The name was either explicitly provided by the user
		// or has been agreed upon via some logic.
		//std::unordered_map<std::string, SessionGroup> mSessionGroups;

		void asyncSetSocket(		
			std::string name,
			std::unique_ptr<BoostSocketInterface> handel);

		void asyncGetSocket(std::shared_ptr<ChannelBase> chl);


		void cancelPendingChannel(ChannelBase* chl);

		//bool isEmpty() const;

		bool hasSubscriptions() const;
		//bool userModeHasSubscriptions() const;
		//void removePendingSockets();

		//void removeSession(const SessionBase* ep/*, const std::optional<std::chrono::milliseconds>& waitTime = {}*/);
		void unsubscribe(SessionBase* ep);

		void stopListening();

		void subscribe(std::shared_ptr<SessionBase>& session);

		SocketGroupList::iterator getSocketGroup(const std::string& name, u64 id);

		u64 mPort;
		boost::asio::ip::tcp::endpoint mAddress;

		void bind(u32 port, std::string ip, boost::system::error_code& ec);
		void start();
		void stop();
		bool stopped() const;
		bool isListening() const { return mListening; };


		std::string print() const;
	};

}
