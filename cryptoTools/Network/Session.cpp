#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Network/IoBuffer.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>

#include <boost/lexical_cast.hpp>

#include <sstream>
#include <random>

namespace osuCrypto {

	//extern std::vector<std::string> split(const std::string &s, char delim);


	void Session::start(IOService& ioService, std::string remoteIP, u32 port, SessionMode type, std::string name)
	{
		if (mBase && mBase->mStopped == false)
			throw std::runtime_error("rt error at " LOCATION);

		mBase.reset(new SessionBase(ioService.mIoService));
		mBase->mIP = (remoteIP);
		mBase->mPort = (port);
		mBase->mMode = (type);
		mBase->mIOService = &(ioService);
		mBase->mStopped = (false);
		mBase->mName = (name);


		if (type == SessionMode::Server)
		{
			ioService.aquireAcceptor(mBase);
		}
		else
		{
			std::random_device rd;
			mBase->mSessionID = (1ULL << 32) * rd() + rd();

			boost::asio::ip::tcp::resolver resolver(ioService.mIoService);
			boost::asio::ip::tcp::resolver::query query(remoteIP, boost::lexical_cast<std::string>(port));
			mBase->mRemoteAddr = *resolver.resolve(query);
		}
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

	Session::Session(const Session & v)
		: mBase(v.mBase)
	{
		++mBase->mRealRefCount;
	}

	Session::Session(const std::shared_ptr<SessionBase>& c)
		: mBase(c)
	{ }

	Session::~Session()
	{
		--mBase->mRealRefCount;
		if (mBase->mRealRefCount == 0)
			mBase->stop();
	}

	std::string Session::getName() const
	{
		if (mBase)
			return mBase->mName;
		else
			throw std::runtime_error(LOCATION);
	}

	u64 Session::getSessionID() const
	{
		if (mBase)
			return mBase->mSessionID;
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
		// if the user does not provide a local name, use the following.
		if (localName == "") {
			if (remoteName != "") throw std::runtime_error("remote name must be empty is local name is empty. " LOCATION);

			std::lock_guard<std::mutex> lock(mBase->mAddChannelMtx);
			localName = "_autoName_" + std::to_string(mBase->mAnonymousChannelIdx++);
		}


		// make the remote name match the local name if empty
		if (remoteName == "") remoteName = localName;

		if (mBase->mStopped == true) throw std::runtime_error("rt error at " LOCATION);


		// construct the basic channel. Has no socket.
		Channel chl(*this, localName, remoteName);
		//auto chlBase = chl.mBase;
		//auto epBase = mBase;

		if (mBase->mMode == SessionMode::Server)
		{
			// the acceptor will do the handshake, set chl.mHandel and
			// kick off any send and receives which may happen after this
			// call but before the handshake completes
			mBase->mAcceptor->asyncGetSocket(chl.mBase);
		}
		else
		{
			chl.mBase->asyncConnectToServer(mBase->mRemoteAddr);
		}

		return (chl);
	}


	void Session::stop()
	{
		mBase->stop();
	}

	void SessionBase::stop()
	{
		if (mStopped == false)
		{
			mStopped = true;
			if (mAcceptor)
				mAcceptor->unsubscribe(this);
			mWorker.reset(nullptr);
		}
	}

	SessionBase::~SessionBase()
	{
		stop();
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

	//void SessionBase::cancelPendingConnection(ChannelBase * chl)
	//{
	//}

}