#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/IOService.h>
namespace osuCrypto {

	Channel::Channel(
		Session& endpoint,
		std::string localName,
		std::string remoteName)
		:
		mBase(new ChannelBase(endpoint, localName, remoteName))
	{}

	Channel::Channel(IOService& ios, SocketInterface * sock)
		: mBase(new ChannelBase(ios, sock))
	{}


	ChannelBase::ChannelBase(
		Session& endpoint,
		std::string localName,
		std::string remoteName)
		:
		mIos(endpoint.getIOService()),
		mWork(new boost::asio::io_service::work(endpoint.getIOService().mIoService)),
		mSession(endpoint.mBase),
		mRemoteName(remoteName),
		mLocalName(localName),
		mRecvStatus(Channel::Status::Normal),
		mSendStatus(Channel::Status::Normal),
		mHandle(nullptr),
		mTimer(endpoint.getIOService().mIoService),
		mSendStrand(endpoint.getIOService().mIoService),
		mRecvStrand(endpoint.getIOService().mIoService),
		mOpenProm(),
		mOpenFut(mOpenProm.get_future()),
		mOpenCount(0),
		mRecvSocketSet(false),
		mSendSocketSet(false),
		mOutstandingSendData(0),
		mMaxOutstandingSendData(0),
		mTotalSentData(0),
		mSendQueueEmptyFuture(mSendQueueEmptyProm.get_future()),
		mRecvQueueEmptyFuture(mRecvQueueEmptyProm.get_future())
#ifdef CHANNEL_LOGGING
		, mOpIdx(0)
#endif
	{
	}

	ChannelBase::ChannelBase(IOService& ios, SocketInterface * sock)
		:
		mIos(ios),
		mWork(new boost::asio::io_service::work(ios.mIoService)),
		mRecvStatus(Channel::Status::Normal),
		mSendStatus(Channel::Status::Normal),
		mHandle(sock),
		mTimer(ios.mIoService),
		mSendStrand(ios.mIoService),
		mRecvStrand(ios.mIoService),
		mOpenProm(),
		mOpenFut(mOpenProm.get_future()),
		mOpenCount(0),
		mRecvSocketSet(true),
		mSendSocketSet(true),
		mOutstandingSendData(0),
		mMaxOutstandingSendData(0),
		mTotalSentData(0),
		mSendQueueEmptyFuture(mSendQueueEmptyProm.get_future()),
		mRecvQueueEmptyFuture(mRecvQueueEmptyProm.get_future())
#ifdef CHANNEL_LOGGING
		, mOpIdx(0)
#endif
	{
		mOpenProm.set_value();
	}

	Channel::~Channel()
	{
	}


	void ChannelBase::asyncConnectToServer(const boost::asio::ip::tcp::endpoint& address)
	{
		mHandle.reset(new BoostSocketInterface(
			boost::asio::ip::tcp::socket(getIOService().mIoService)));

		mSendSizeBuff = 0;
		mConnectCallback = [this, address](const boost::system::error_code& ec)
		{
			auto& sock = ((BoostSocketInterface*)mHandle.get())->mSock;

			if (ec)
			{
				//std::cout << "connect failed, " << this->mLocalName << " " << ec.value() << " " << ec.message() << ".  " << address.address().to_string() << std::endl;
				// try to connect again...
				if (stopped() == false)
				{
					mTimer.expires_from_now(boost::posix_time::millisec(10));
					mTimer.async_wait([&](const boost::system::error_code& ec)
					{
						if (ec)
						{
							std::cout << "unknown timeout error: " << ec.message() << std::endl;
						}
						sock.close();
						sock.async_connect(address, mConnectCallback);
					});
				}
				else
					mOpenProm.set_exception(std::make_exception_ptr(
						SocketConnectError("Session tried to connect but the channel has stopped. "  LOCATION)));
			}
			else
			{
				boost::asio::ip::tcp::no_delay option(true);
				sock.set_option(option);

				std::stringstream sss;
				sss << mSession->mName << '`'
					<< mSession->mSessionID << '`'
					<< mLocalName << '`'
					<< mRemoteName;

				mSendStrand.post([this, str = sss.str()]() mutable
				{
					auto op = std::unique_ptr<IOOperation>(new MoveChannelBuff<std::string>(std::move(str)));
#ifdef CHANNEL_LOGGING
					auto idx = op->mIdx = base->mOpIdx++;
#endif
					mSendQueue.emplace_front(std::move(op));
					mSendSocketSet = true;

					auto ii = ++mOpenCount;
					if (ii == 2) mOpenProm.set_value();
#ifdef CHANNEL_LOGGING
					base->mLog.push("initSend' #" + ToString(idx) + " , opened = " + ToString(ii == 2) + ", start = " + ToString(true));
#endif
					mSession->mIOService->sendOne(this);
				});


				mRecvStrand.post([this]()
				{
					mRecvSocketSet = true;

					auto ii = ++mOpenCount;
					if (ii == 2) mOpenProm.set_value();

					auto startRecv = mRecvQueue.size() > 0;
#ifdef CHANNEL_LOGGING
					base->mLog.push("initRecv' , opened = " + ToString(ii == 2) + ", start = " + ToString(startRecv));
#endif

					if (startRecv)
					{
						mSession->mIOService->receiveOne(this);
					}
				});
			}
		};


		((BoostSocketInterface*)mHandle.get())->mSock.async_connect(address, mConnectCallback);
	}



	std::string Channel::getName() const
	{
		return mBase->mLocalName;
	}

	Channel & Channel::operator=(Channel && move)
	{
		mBase = std::move(move.mBase);
		return *this;
	}

	Channel & Channel::operator=(const Channel & copy)
	{
		mBase = copy.mBase;
		return *this;
	}

	bool Channel::isConnected()
	{
		return mBase->mSendSocketSet  && mBase->mRecvSocketSet;
	}

	bool Channel::waitForConnection(std::chrono::milliseconds timeout)
	{
		auto status = mBase->mOpenFut.wait_for(timeout);
		if (status != std::future_status::ready)
			return false;
		mBase->mOpenFut.get();
		return true;
	}

	void Channel::waitForConnection()
	{
		mBase->mOpenFut.get();
	}

	void Channel::close()
	{
		if (mBase) mBase->close();
		mBase = nullptr;
	}

	void Channel::cancel()
	{
		if (mBase) mBase->cancel();
	}

	void ChannelBase::cancel()
	{
		if (stopped() == false)
		{
			mSendStatus = Channel::Status::Stopped;
			mRecvStatus = Channel::Status::Stopped;

			if (mHandle) mHandle->close();
			if (mSession && mSession->mAcceptor) mSession->mAcceptor->cancelPendingChannel(this);

			try { mOpenFut.get(); }
			catch (SocketConnectError& )
			{
				// The socket has never started.
				// We can simply remove all the queued items.
				cancelRecvQueuedOperations();
				cancelSendQueuedOperations();
			}

			mSendStrand.dispatch([&]() {
				if (mSendQueue.size() == 0 && mSendQueueEmpty == false)
					mSendQueueEmptyProm.set_value();
			});

			mRecvStrand.dispatch([&]() {
				if (mRecvQueue.size() == 0 && mRecvQueueEmpty == false)
					mRecvQueueEmptyProm.set_value();
				else if (activeRecvSizeError())
					cancelRecvQueuedOperations();
			});

			mSendQueueEmptyFuture.get();
			mRecvQueueEmptyFuture.get();

			mHandle.reset(nullptr);
			mWork.reset(nullptr);
		}

	}

	void ChannelBase::close()
	{
		if (stopped() == false)
		{
			mOpenFut.get();

			mSendStrand.dispatch([&]() {
				mSendStatus = Channel::Status::Stopped;
				if (mSendQueue.size() == 0 && mSendQueueEmpty == false)
				{
					mSendQueueEmpty = true;
					mSendQueueEmptyProm.set_value();
				}
			});

			mRecvStrand.dispatch([&]() {
				mRecvStatus = Channel::Status::Stopped;
				if (mRecvQueue.size() == 0 && mRecvQueueEmpty == false)
				{
					mRecvQueueEmpty = true;
					mRecvQueueEmptyProm.set_value();
				}
				else if (activeRecvSizeError())
				{
					cancelRecvQueuedOperations();
				}
			});

			mSendQueueEmptyFuture.get();
			mRecvQueueEmptyFuture.get();

			// ok, the send and recv queues are empty. Lets close the socket
			if (mHandle)mHandle->close();

			mHandle.reset(nullptr);
			mWork.reset(nullptr);

#ifdef CHANNEL_LOGGING
			mLog.push("Closed");
#endif
		}
	}




	void ChannelBase::cancelSendQueuedOperations()
	{
		mSendStrand.dispatch([this]() {

			//if (mHandle)
			//	mHandle->close();
			if (mSendQueueEmpty == false)
			{

				while (mSendQueue.size())
				{
					auto& front = mSendQueue.front();

#ifdef CHANNEL_LOGGING
					mLog.push("cancel send #" + ToString(front->mIdx));
#endif
					//delete front->mContainer;

					auto e_ptr = std::make_exception_ptr(std::runtime_error("Channel Error: " + mSendErrorMessage));
					front->mPromise.set_exception(e_ptr);

					//delete front;
					mSendQueue.pop_front();
				}

#ifdef CHANNEL_LOGGING
				mLog.push("send queue empty");
#endif
				mSendQueueEmpty = true;
				mSendQueueEmptyProm.set_value();
			}
		});
	}


	void ChannelBase::cancelRecvQueuedOperations()
	{
		mRecvStrand.dispatch([this]() {

			if (mRecvQueueEmpty == false)
			{


				//if (mHandle)
				//	mHandle->close();

				while (mRecvQueue.size())
				{
					auto& front = mRecvQueue.front();

#ifdef CHANNEL_LOGGING
					mLog.push("cancel recv #" + ToString(front->mIdx));
#endif
					//delete front->mContainer;

					auto e_ptr = std::make_exception_ptr(std::runtime_error("Channel Error: " + mRecvErrorMessage));
					front->mPromise.set_exception(e_ptr);

					//delete front;
					mRecvQueue.pop_front();
				}


#ifdef CHANNEL_LOGGING
				mLog.push("recv queue empty");
#endif
				mRecvQueueEmpty = true;
				mRecvQueueEmptyProm.set_value();
			}
		});
	}

	std::string Channel::getRemoteName() const
	{
		return mBase->mRemoteName;
	}

	Session Channel::getSession() const
	{
		if (mBase->mSession)
			return mBase->mSession;
		else
			throw std::runtime_error("no session. " LOCATION);
	}


	void Channel::resetStats()
	{
		mBase->mTotalSentData = 0;
		mBase->mTotalRecvData = 0;
		mBase->mMaxOutstandingSendData = 0;
		mBase->mOutstandingSendData = 0;
	}

	u64 Channel::getTotalDataSent() const
	{
		return mBase->mTotalSentData;
	}

	u64 Channel::getTotalDataRecv() const
	{
		return mBase->mTotalRecvData;
	}

	u64 Channel::getMaxOutstandingSendData() const
	{
		return (u64)mBase->mMaxOutstandingSendData;
	}

	void Channel::dispatch(std::unique_ptr<IOOperation> op)
	{
		mBase->getIOService().dispatch(mBase.get(), std::move(op));
	}

	void ChannelBase::setRecvFatalError(std::string reason)
	{
		mRecvStrand.dispatch([&, reason]() {

#ifdef CHANNEL_LOGGING
			mLog.push("Recv error: " + reason);
#endif
			mRecvErrorMessage += (reason + "\n");
			mRecvStatus = Channel::Status::Stopped;
			cancelRecvQueuedOperations();
		});
	}

	void ChannelBase::setSendFatalError(std::string reason)
	{
		mSendStrand.dispatch([&, reason]() {

#ifdef CHANNEL_LOGGING
			mLog.push("Send error: " + reason);
#endif
			mSendErrorMessage = reason;
			mSendStatus = Channel::Status::Stopped;
			cancelSendQueuedOperations();
		});
	}

	void ChannelBase::setBadRecvErrorState(std::string reason)
	{
		mRecvStrand.dispatch([&, reason]() {

			if (mRecvStatus == Channel::Status::Normal)
			{
				mRecvErrorMessage = reason;
			}
		});
	}

	void ChannelBase::clearBadRecvErrorState()
	{
		mRecvStrand.dispatch([&]() {

			if (activeRecvSizeError() && mRecvStatus == Channel::Status::Normal)
			{
				mRecvErrorMessage = "";
			}
		});
	}
}
