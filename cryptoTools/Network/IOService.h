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

namespace osuCrypto
{

	class Acceptor;
	class IOOperation;
    class Endpoint;
    class Channel;
    class ChannelBase;

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

        // A list containing futures for the endpoint that use this IO service. Each is fulfilled when the endpoint is finished with this class.
        std::list<std::shared_future<void>> mEndpointStopFutures;

        void receiveOne(ChannelBase* socket);

        void sendOne(ChannelBase* socket);

        void startSocket(ChannelBase* chl);

        // Used to queue up asynchronous socket operations.
        void dispatch(ChannelBase* socket, std::unique_ptr<IOOperation> op);

        // Gives a new endpoint which is a host endpoint the acceptor which provides sockets. 
        Acceptor* getAcceptor(Endpoint& endpoint);

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
		std::unordered_map<std::string, std::pair<BoostSocketInterface*, ChannelBase*>> mSocketChannelPairs;

		void asyncSetSocket(
			std::string endpointName,
			std::string localChannelName,
			std::string remoteChannelName,
			BoostSocketInterface* handel);

		void asyncGetSocket(ChannelBase& chl);

		void remove(std::string endpoint, std::string localName, std::string remoteName);

		u64 mPort;
		boost::asio::ip::tcp::endpoint mAddress;

		void bind(u32 port, std::string ip);
		void start();
		void stop();
		bool stopped() const;
	};

}
