#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/SocketAdapter.h>

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
//#include <optional>

namespace osuCrypto
{

	class Acceptor;
	class IOOperation;
    class Endpoint;
    class Channel;
    class ChannelBase;
	struct EndpointBase;

    std::vector<std::string> split(const std::string &s, char delim);

    class IOService
    {
        friend class Channel;
        friend class Endpoint;

    public:

        IOService(const IOService&) = delete;

        // Constructor for the IO service that services network IO operations.
        // threadCount is The number of threads that should be used to service IO operations. 0 = use # of CPU cores.
        IOService(u64 threadCount = 0);
        ~IOService();

        boost::asio::io_service mIoService;

        std::unique_ptr<boost::asio::io_service::work> mWorker;

        std::list<std::thread> mWorkerThrds;

        // The list of acceptor objects that hold state about the ports that are being listened to. 
        std::list<Acceptor> mAcceptors;

        void printErrorMessages(bool v);

        // indicates whether stop() has been called already.
        bool mStopped;

        // The mutex the protects sensitive objects in this class. 
        std::mutex mMtx;

        void receiveOne(ChannelBase* socket);

        void sendOne(ChannelBase* socket);

        void startSocket(ChannelBase* chl, std::unique_ptr<BoostSocketInterface> socket);

        // Used to queue up asynchronous socket operations.
        void dispatch(ChannelBase* socket, std::unique_ptr<IOOperation> op);

        // Gives a new endpoint which is a host endpoint the acceptor which provides sockets. 
        Acceptor* getAcceptor(std::string ip, i32 port);

        // Shut down the IO service. WARNING: blocks until all Channels and Endpoints are stopped.
        void stop();

        bool mPrint;
    };


	class Acceptor
	{

	public:
		Acceptor() = delete;
		Acceptor(const Acceptor&) = delete;

		Acceptor(IOService& ioService);
		~Acceptor();

		std::promise<void> mStoppedListeningPromise, mSocketChannelPairsRemovedProm;
		std::future<void> mStoppedListeningFuture, mSocketChannelPairsRemovedFuture;

		IOService& mIOService;

		boost::asio::ip::tcp::acceptor mHandle;

		std::atomic<bool> mStopped;
		std::mutex mSocketChannelPairsMtx;


		struct EndpointGroup
		{
			EndpointGroup() = default;
			EndpointGroup(const EndpointGroup&) = delete;
			EndpointGroup(EndpointGroup&&) = default;

			struct NamedSocket {
				std::string mRemoteName, mLocalName;
				std::unique_ptr<BoostSocketInterface> mSocket;
			};

			bool isEmpty() const
			{
				return mSockets.size() == 0 && mChannels.size() == 0;
			}

			bool hasPendingChannels() const
			{
				return mChannels.size();
			}


			void print();
			//void waitForChannels(std::mutex& mtx, const std::optional<std::chrono::milliseconds>& waitTime = {});
			//std::promise<void> mProm;
			//std::future<void> mFuture;
			u64 mSuccessfulConnections = 0;
			std::string mName;
			std::shared_ptr<EndpointBase> mBase;
			std::list<NamedSocket> mSockets;
			std::list<std::shared_ptr<ChannelBase>> mChannels;
		};

		// A list of EndpointGroups containing unnamed endpointed
		// created by the server.
		std::list<EndpointGroup> mAnonymousServerEps;

		// A list of EndpointGroups containing unnamed endpointed
		// created by the server.
		std::list<EndpointGroup> mAnonymousClientEps;

		// A map of endpoint groups which have well defined name.
		// The name was either explicitly provided by the user
		// or has been agreed upon via some logic.
		std::unordered_map<std::string, EndpointGroup> mEndpointGroups;

		void asyncSetSocket(		
			std::string name,
			std::unique_ptr<BoostSocketInterface> handel);

		void asyncGetSocket(std::shared_ptr<ChannelBase> chl);

		bool isEmpty() const;

		bool hasPendingsChannels() const;

		void removePendingSockets();

		//void removeEndpoint(const EndpointBase* ep, const std::optional<std::chrono::milliseconds>& waitTime = {});

		//void remove(std::string endpoint, std::string localName, std::string remoteName);

		u64 mPort;
		boost::asio::ip::tcp::endpoint mAddress;

		void bind(u32 port, std::string ip);
		void start();
		void stop();
		bool stopped() const;
	};

}
