#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Network/IoBuffer.h>
#include <cryptoTools/Common/Log.h>

#include <boost/lexical_cast.hpp>

#include <sstream>
#include <random>

namespace osuCrypto {

	//extern std::vector<std::string> split(const std::string &s, char delim);


	void Session::start(IOService& ioService, std::string remoteIP, u32 port, SessionMode type, std::string name)
	{
		if (mBase && mBase->mStopped == false)
			throw std::runtime_error("rt error at " LOCATION);

		mBase.reset(new SessionBase);
		mBase->mIP = (remoteIP);
		mBase->mPort = (port);
		mBase->mMode = (type);
		mBase->mIOService = &(ioService);
		mBase->mStopped = (false);
		mBase->mName = (name);

		if (type == SessionMode::Server)
		{
			mBase->mAcceptor = ioService.getAcceptor(remoteIP, port);
		}
		else
		{
			boost::asio::ip::tcp::resolver resolver(ioService.mIoService);
			boost::asio::ip::tcp::resolver::query query(remoteIP, boost::lexical_cast<std::string>(port));
			mBase->mRemoteAddr = *resolver.resolve(query);
		}

		//std::lock_guard<std::mutex> lock(ioService.mMtx);
		//ioService.mSessionStopFutures.push_back(mBase->mDoneFuture);

	}

	void Session::start(IOService& ioService, std::string address, SessionMode host, std::string name)
	{
		auto vec = split(address, ':');

		auto ip = vec[0];
		auto port = 1212;
		if (vec.size() > 1)
		{
			std::stringstream ss(vec[1]);
			ss >> port;
		}

		start(ioService, ip, port, host, name);

	}

	// See start(...)

	Session::Session(IOService & ioService, std::string address, SessionMode type, std::string name)
	{
		start(ioService, address, type, name);
	}

	// See start(...)

	Session::Session(IOService & ioService, std::string remoteIP, u32 port, SessionMode type, std::string name)
	{
		start(ioService, remoteIP, port, type, name);
	}


	// Default constructor

	Session::Session()
	{ }

	Session::Session(std::shared_ptr<SessionBase>& c)
		: mBase(c)
	{ }

	Session::~Session()
	{
		//stop();
	}

	std::string Session::getName() const
	{
		if (mBase)
			return mBase->mName;
		else
			throw std::runtime_error(LOCATION);
	}

	IOService & Session::getIOService() {
		if (mBase)
			return *mBase->mIOService;
		else
			throw std::runtime_error(LOCATION);
	}


	Channel Session::addChannel(std::string localName, std::string remoteName)
	{
		bool firstAnonymousChl = false;
		{
			std::lock_guard<std::mutex> lock(mBase->mAddChannelMtx);
			if (mBase->mName == "" && isHost() == false)
			{
				// pick a random endpoint name...
				firstAnonymousChl = true;
				std::random_device rd;
				mBase->mName = "ep_" + std::to_string(rd()) + std::to_string(rd());
			}

			// if the user does not provide a local name, use the following.
			if (localName == "") {
				if (remoteName != "") throw std::runtime_error("remote name must be empty is local name is empty. " LOCATION);
				localName = "_autoName_" + std::to_string(mBase->mAnonymousChannelIdx++);
			}
		}


		// make the remote name match the local name if empty
		if (remoteName == "") remoteName = localName;

		if (mBase->mStopped == true) throw std::runtime_error("rt error at " LOCATION);


		// construct the basic channel. Has no socket.
		Channel chl(*this, localName, remoteName);
		auto chlBase = chl.mBase;
		auto epBase = mBase;

		if (mBase->mMode == SessionMode::Server)
		{
			// the acceptor will do the handshake, set chl.mHandel and
			// kick off any send and receives which may happen after this
			// call but before the handshake completes
			mBase->mAcceptor->asyncGetSocket(chl.mBase);
		}
		else
		{
			chlBase->mHandle.reset(new BoostSocketInterface(getIOService().mIoService));

			auto initialCallback = new std::function<void(const boost::system::error_code&)>();
			auto timer = new boost::asio::deadline_timer(getIOService().mIoService, boost::posix_time::milliseconds(10));




			*initialCallback =
				[epBase, chlBase, timer, initialCallback, localName, remoteName, firstAnonymousChl]
			(const boost::system::error_code& ec)
			{
				if (ec && chlBase->stopped() == false && epBase->mStopped == false)
				{
					// tell the io service to wait 10 ms and then try again...
					timer->async_wait([epBase, chlBase, timer, initialCallback](const boost::system::error_code& ec)
					{
						if (chlBase->stopped() || ec)
						{
							auto e_ptr = std::make_exception_ptr(std::runtime_error(LOCATION));
							chlBase->mOpenProm.set_exception(e_ptr);
							delete initialCallback;
							delete timer;
						}
						else
						{
							// try to connect again...
							((BoostSocketInterface*)chlBase->mHandle.get())->mSock.async_connect(epBase->mRemoteAddr, *initialCallback);
						}
					});
				}
				else if (!ec)
				{
					//std::cout << IoStream::lock << "        connected "<< localName  << std::endl << IoStream::unlock;

					boost::asio::ip::tcp::no_delay option(true);
					((BoostSocketInterface*)chlBase->mHandle.get())->mSock.set_option(option);

					std::stringstream ss;
					ss << epBase->mName << char('`') << localName << char('`') << remoteName;

					// append a special symbol to denote that this EP name was chosen at random.
					if (firstAnonymousChl) ss << "`#";

					//if (firstAnonymousChl)
					//	std::this_thread::sleep_for(std::chrono::microseconds(100));

					chlBase->mSendStrand.post([epBase, chlBase, str = ss.str()]() mutable
					{
						auto op = std::unique_ptr<IOOperation>(new MoveChannelBuff<std::string>(std::move(str)));
#ifdef CHANNEL_LOGGING
						auto idx = op->mIdx = base->mOpIdx++;
#endif
						chlBase->mSendQueue.emplace_front(std::move(op));
						chlBase->mSendSocketSet = true;

						auto ii = ++chlBase->mOpenCount;
						if (ii == 2) chlBase->mOpenProm.set_value();
#ifdef CHANNEL_LOGGING
						base->mLog.push("initSend' #" + ToString(idx) + " , opened = " + ToString(ii == 2) + ", start = " + ToString(true));
#endif
						epBase->mIOService->sendOne(chlBase.get());
					});


					chlBase->mRecvStrand.post([epBase, chlBase]()
					{
						chlBase->mRecvSocketSet = true;

						auto ii = ++chlBase->mOpenCount;
						if (ii == 2) chlBase->mOpenProm.set_value();

						auto startRecv = chlBase->mRecvQueue.size() > 0;
#ifdef CHANNEL_LOGGING
						base->mLog.push("initRecv' , opened = " + ToString(ii == 2) + ", start = " + ToString(startRecv));
#endif

						if (startRecv)
						{
							epBase->mIOService->receiveOne(chlBase.get());
						}
					});

					delete initialCallback;
					delete timer;
				}
				else
				{
					auto e_ptr = std::make_exception_ptr(std::runtime_error(LOCATION));
					chlBase->mOpenProm.set_exception(e_ptr);
					delete initialCallback;
					delete timer;
				}
			};

			((BoostSocketInterface*)chlBase->mHandle.get())->mSock.async_connect(epBase->mRemoteAddr, *initialCallback);
		}

		return (chl);
	}


	void Session::stop()
	{
		mBase->mStopped = true;

		if (mBase->mAcceptor)
			mBase->mAcceptor->removeSession(mBase);
	}

	bool Session::stopped() const
	{
		return mBase->mStopped;
	}

	u32 Session::port() const
	{
		return mBase->mPort;
	}
	std::string Session::IP() const
	{
		return mBase->mIP;
	}
	bool Session::isHost() const { return mBase->mMode == SessionMode::Server; }

}