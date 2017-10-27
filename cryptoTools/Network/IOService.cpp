#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Finally.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IoBuffer.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/SocketAdapter.h>

#include <stdio.h>
#include <algorithm>
#include <sstream>

namespace osuCrypto
{


	Acceptor::Acceptor(IOService& ioService)
		:
		//mSocketChannelPairsRemovedFuture(mSocketChannelPairsRemovedProm.get_future()),
		mPendingSocketsEmptyFuture(mPendingSocketsEmptyProm.get_future()),
		mStoppedFuture(mStoppedPromise.get_future()),
		mIOService(ioService),
		mStrand(ioService.mIoService),
		mHandle(ioService.mIoService),
		mStopped(false),
		mPort(0)
	{
	}

	Acceptor::~Acceptor()
	{
		stop();
	}

	void Acceptor::bind(u32 port, std::string ip, boost::system::error_code& ec)
	{
		auto pStr = std::to_string(port);
		mPort = port;

		boost::asio::ip::tcp::resolver resolver(mIOService.mIoService);
		boost::asio::ip::tcp::resolver::query
			query(ip, pStr);

		auto addrIter = resolver.resolve(query, ec);

		if (ec)
		{
			return;
		}

		mAddress = *addrIter;

		mHandle.open(mAddress.protocol());
		mHandle.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

		mHandle.bind(mAddress, ec);

		if (mAddress.port() != port)
			throw std::runtime_error("rt error at " LOCATION);

		if (ec)
		{
			return;
			//std::cout << "network address bind error: " << ec.message() << std::endl;

			//throw std::runtime_error(ec.message());
		}


		//std::promise<void> mStoppedListeningPromise, mSocketChannelPairsRemovedProm;
		//std::future<void> mStoppedListeningFuture, mSocketChannelPairsRemovedFuture;
		mHandle.listen(boost::asio::socket_base::max_connections);
	}

	void Acceptor::start()
	{
		mStrand.dispatch([&]()
		{
			if (isListening())
			{
				mPendingSockets.emplace_back(mIOService.mIoService);
				auto sockIter = mPendingSockets.end(); --sockIter;

				//BoostSocketInterface* newSocket = new BoostSocketInterface(mIOService.mIoService);
				mHandle.async_accept(sockIter->mSock, [sockIter, this](const boost::system::error_code& ec)
				{
					start();

					if (!ec)
					{
						boost::asio::ip::tcp::no_delay option(true);
						sockIter->mSock.set_option(option);
						sockIter->mBuff.resize(sizeof(u32));

						sockIter->mSock.async_receive(boost::asio::buffer((char*)sockIter->mBuff.data(), sockIter->mBuff.size()),
							[sockIter, this](const boost::system::error_code& ec2, u64 bytesTransferred)
						{
							if (!ec2 && bytesTransferred == 4)
							{
								auto size = *(u32*)sockIter->mBuff.data();
								sockIter->mBuff.resize(size);

								sockIter->mSock.async_receive(boost::asio::buffer((char*)sockIter->mBuff.data(), sockIter->mBuff.size()),
									mStrand.wrap([sockIter, this](const boost::system::error_code& ec3, u64 bytesTransferred2)
								{
									if (!ec3 && bytesTransferred2 == sockIter->mBuff.size())
									{
										asyncSetSocket(
											std::move(sockIter->mBuff),
											std::move(std::unique_ptr<BoostSocketInterface>(
												new BoostSocketInterface(std::move(sockIter->mSock)))));
									}

									mPendingSockets.erase(sockIter);
									if (stopped() && mPendingSockets.size() == 0)
										mPendingSocketsEmptyProm.set_value();
								}));

							}
							else
							{
								//std::cout << "async_accept error, failed to receive first header on connection handshake."
								//	<< " Other party may have closed the connection. "
								//	<< ((ec2 != 0) ? "Error code:" + ec2.message() : " received " + ToString(bytesTransferred) + " / 4 bytes") << "  " << LOCATION << std::endl;
								mStrand.dispatch([&, sockIter]()
								{
									mPendingSockets.erase(sockIter);
									if (stopped() && mPendingSockets.size() == 0)
										mPendingSocketsEmptyProm.set_value();
								});
							}

						});
					}
					else
					{
						
						mStrand.dispatch([&, sockIter]()
						{
							mPendingSockets.erase(sockIter);
							if (stopped() && mPendingSockets.size() == 0)
								mPendingSocketsEmptyProm.set_value();
						});
					}
				});
			}
			else
			{
				//mStrand.dispatch([&]()
				//{
				//	if (stopped() && mPendingSockets.size() == 0)
				//		mPendingSocketsEmptyProm.set_value();
				//});
			}
		});

	}

	void Acceptor::stop()
	{
		if (mStopped == false)
		{
			mStrand.dispatch([&]() {
				if (mStopped == false)
				{
					mStopped = true;
					mListening = false;

					// stop listening.

					//std::cout << IoStream::lock << " accepter stop() " << mPort << std::endl << IoStream::unlock;

					mHandle.close();

					// cancel any sockets which have not completed the handshake.
					for (auto& pendingSocket : mPendingSockets)
						pendingSocket.mSock.close();

					// if there were no pending sockets, set the promise
					if (mPendingSockets.size() == 0)
						mPendingSocketsEmptyProm.set_value();

					// no subscribers, we can set the promise now.
					if (hasSubscriptions() == false)
						mStoppedPromise.set_value();
				}
			});

			// wait for the pending events.
			std::chrono::seconds timeout(4);
			std::future_status status = mPendingSocketsEmptyFuture.wait_for(timeout);

			while (status == std::future_status::timeout)
			{
				status = mPendingSocketsEmptyFuture.wait_for(timeout);
				std::cout << "waiting on acceptor to close "<< mPendingSockets.size() <<" pending socket" << std::endl;
			}

			mPendingSocketsEmptyFuture.get();
			mStoppedFuture.get();

		}
	}


	bool Acceptor::hasSubscriptions() const
	{
		for (auto& a : mGroups)
			if (a.hasSubscriptions())
				return true;

		return false;
	}
	void Acceptor::stopListening()
	{
		if (isListening())
		{
			mStrand.dispatch([&]() {
				if (hasSubscriptions() == false)
				{

					mListening = false;

					//std::cout << IoStream::lock << "stop listening " << std::endl << IoStream::unlock;
					mHandle.close();

					if (stopped() && hasSubscriptions() == false)
						mStoppedPromise.set_value();
				}
			});
		}
	}

	void Acceptor::unsubscribe(SessionBase* session)
	{
		std::promise<void> p;
		std::future<void> f(p.get_future());
		auto iter = session->mGroup;

		mStrand.dispatch([&, iter]() {
			iter->mBase.reset();

			if (iter->hasSubscriptions() == false)
			{
				iter->removeMapping();
				mGroups.erase(iter);
			}

			// if no one else wants us to listen, stop listening
			if (hasSubscriptions() == false)
				stopListening();

			p.set_value();
		});

		f.get();
	}

	void Acceptor::subscribe(std::shared_ptr<SessionBase>& session)
	{
		std::promise<void> p;
		std::future<void> f = p.get_future();

		session->mAcceptor = this;

		mStrand.dispatch([&]() {

			if (mStopped)
			{
				auto ePtr = std::make_exception_ptr(
					std::runtime_error("can not subscribe to a stopped Acceptor."));
				p.set_exception(ePtr);
			}
			else
			{
				mGroups.emplace_back();
				auto iter = mGroups.end(); --iter;

				iter->mBase = session;
				session->mGroup = iter;

				auto key = session->mName;
				auto& collection = mUnclaimedGroups[key];
				collection.emplace_back(iter);
				auto deleteIter = collection.end(); --deleteIter;

				iter->removeMapping = [&, deleteIter, key]()
				{
					collection.erase(deleteIter);
					if (collection.size() == 0)
						mUnclaimedGroups.erase(mUnclaimedGroups.find(key));
				};

				if (mListening == false)
				{
					mListening = true;
					boost::system::error_code ec;
					bind(session->mPort, session->mIP, ec);

					if (ec) {
						auto ePtr = std::make_exception_ptr(
							std::runtime_error("network bind error: " + ec.message()));
						p.set_exception(ePtr);
					}

					start();
				}

				p.set_value();
			}
		});

		// may throw
		f.get();
	}

	Acceptor::SocketGroupList::iterator Acceptor::getSocketGroup(const std::string & sessionName, u64 sessionID)
	{

		auto unclaimedSocketIter = mUnclaimedSockets.find(sessionName);
		if (unclaimedSocketIter != mUnclaimedSockets.end())
		{
			auto& sockets = unclaimedSocketIter->second;
			auto matchIter = std::find_if(sockets.begin(), sockets.end(),
				[&](const SocketGroupList::iterator& g) { return g->mSessionID == sessionID; });

			if (matchIter != sockets.end())
				return *matchIter;
		}

		// there is no socket group for this session. lets create one.
		mSockets.emplace_back();
		auto socketIter = mSockets.end(); --socketIter;

		socketIter->mName = sessionName;
		socketIter->mSessionID = sessionID;

		// add a mapping to indicate that this group is unclaimed
		auto& group = mUnclaimedSockets[sessionName];
		group.emplace_back(socketIter);
		auto deleteIter = group.end(); --deleteIter;

		socketIter->removeMapping = [&group, &socketIter, this, sessionName, deleteIter]() {
			group.erase(deleteIter);
			if (group.size() == 0) mUnclaimedSockets.erase(mUnclaimedSockets.find(sessionName));
		};

		return socketIter;

	}

	void Acceptor::cancelPendingChannel(ChannelBase* chl)
	{
		mStrand.dispatch([=]() {
			auto iter = chl->mSession->mGroup;

			auto chlIter = std::find_if(iter->mChannels.begin(), iter->mChannels.end(),
				[&](const std::shared_ptr<ChannelBase>& c) { return c.get() == chl; });

			if (chlIter != iter->mChannels.end())
			{
				auto ePtr = std::make_exception_ptr(SocketConnectError("Acceptor canceled the socket request. " LOCATION));
				(*chlIter)->mOpenProm.set_exception(ePtr);

				iter->mChannels.erase(chlIter);


				if (iter->hasSubscriptions() == false)
				{
					iter->removeMapping();
					mGroups.erase(iter);

					if (hasSubscriptions() == false)
						stopListening();
				}
			}
		});
	}


	bool Acceptor::stopped() const
	{
		return mStopped;
	}
	std::string Acceptor::print() const
	{
		return std::string();
	}
	//bool Acceptor::userModeIsListening() const
	//{
	//	return false;
	//}
	//std::atomic<int> ccc(0);

	void Acceptor::asyncGetSocket(std::shared_ptr<ChannelBase> chl)
	{
		if (stopped()) throw std::runtime_error(LOCATION);

		mStrand.dispatch([&, chl]() {

			auto& sessionGroup = chl->mSession->mGroup;
			auto& sessionName = chl->mSession->mName;
			auto& sessionID = chl->mSession->mSessionID;


			if (sessionID)
			{
				sessionGroup->add(chl, this);

				if (sessionGroup->hasSubscriptions() == false)
				{
					sessionGroup->removeMapping();
					mGroups.erase(sessionGroup);

					if (hasSubscriptions() == false)
						stopListening();
				}
				return;
			}

			auto socketGroup = mSockets.end();

			auto unclaimedSocketIter = mUnclaimedSockets.find(sessionName);
			if (unclaimedSocketIter != mUnclaimedSockets.end())
			{
				auto& groups = unclaimedSocketIter->second;
				auto matchIter = std::find_if(groups.begin(), groups.end(),
					[&](const SocketGroupList::iterator& g) { return g->hasMatchingSocket(chl); });

				if (matchIter != groups.end())
					socketGroup = *matchIter;
			}

			// add this channel to this group. 
			sessionGroup->add(chl, this);

			// check if we have matching sockets.
			if (socketGroup != mSockets.end())
			{
				// merge the group of sockets into the SessionGroup.
				sessionGroup->merge(*socketGroup, this);

				// erase the mapping for these sockets being unclaimed.
				socketGroup->removeMapping();
				sessionGroup->removeMapping();

				// erase the sockets.
				mSockets.erase(socketGroup);

				// check if we can erase this session group (session closed).
				if (sessionGroup->hasSubscriptions() == false)
				{
					mGroups.erase(sessionGroup);
					if (hasSubscriptions() == false)
						stopListening();
				}
				else
				{
					// If not then add this SessionGroup to the list of claimed
					// sessions. Remove the unclaimed channel mapping
					auto fullKey = sessionName + std::to_string(sessionID);

					auto pair = mClaimedGroups.insert({ fullKey, sessionGroup });
					auto s = pair.second;
					auto location = pair.first;
					if (s == false)
						throw std::runtime_error(LOCATION);
					sessionGroup->removeMapping = [&, location]() { mClaimedGroups.erase(location); };
				}
			}
		});
	}



	void Acceptor::asyncSetSocket(
		std::string name,
		std::unique_ptr<BoostSocketInterface> s)
	{
		mStrand.dispatch([this, name, ss = s.release()]() {
			std::unique_ptr<BoostSocketInterface> sock(ss);

			auto names = split(name, '`');

			if (names.size() != 4)
			{
				std::cout << "bad channel name: " << name << std::endl
					<< "Dropping the connection" << std::endl;
				return;
			}

			auto& sessionName = names[0];
			auto sessionID = std::stoull(names[1]);
			auto& remoteName = names[2];
			auto& localName = names[3];

			details::NamedSocket socket;
			socket.mLocalName = localName;
			socket.mRemoteName = remoteName;
			socket.mSocket = std::move(sock);

			auto fullKey = sessionName + std::to_string(sessionID);
			auto claimedIter = mClaimedGroups.find(fullKey);
			if (claimedIter != mClaimedGroups.end())
			{
				auto group = claimedIter->second;
				group->add(std::move(socket), this);

				if (group->hasSubscriptions() == false)
				{
					group->removeMapping();
					mGroups.erase(group);
					if (hasSubscriptions() == false)
						stopListening();
				}
				return;
			}

			auto socketGroup = getSocketGroup(sessionName, sessionID);

			GroupList::iterator sessionGroup = mGroups.end();

			auto unclaimedLocalIter = mUnclaimedGroups.find(sessionName);
			if (unclaimedLocalIter != mUnclaimedGroups.end())
			{
				auto& groups = unclaimedLocalIter->second;
				auto matchIter = std::find_if(groups.begin(), groups.end(),
					[&](const GroupList::iterator& g) { return g->hasMatchingChannel(socket); });

				if (matchIter != groups.end())
					sessionGroup = *matchIter;
			}

			// add the socket to the SocketGroup
			socketGroup->mSockets.emplace_back(std::move(socket));

			if (sessionGroup != mGroups.end())
			{
				// merge the sockets into the group of cahnnels.
				sessionGroup->merge(*socketGroup, this);

				// make these socketes as claimed and remove the container.
				socketGroup->removeMapping();
				sessionGroup->removeMapping();

				mSockets.erase(socketGroup);

				// check if we can erase this seesion group (session closed).
				if (sessionGroup->hasSubscriptions() == false)
				{
					mGroups.erase(sessionGroup);
					if (hasSubscriptions() == false)
						stopListening();
				}
				else
				{
					// If not then add this SessionGroup to the list of claimed
					// sessions. Remove the unclaimed channel mapping
					auto pair = mClaimedGroups.insert({ fullKey, sessionGroup });
					auto s = pair.second;
					auto location = pair.first;
					if (s == false)
						throw std::runtime_error(LOCATION);

					sessionGroup->removeMapping = [&, location]() { mClaimedGroups.erase(location); };
				}
			}
		});

	}


	extern void split(const std::string &s, char delim, std::vector<std::string> &elems);
	extern std::vector<std::string> split(const std::string &s, char delim);

	IOService::IOService(u64 numThreads)
		:
		mIoService(),
		mStrand(mIoService),
		mWorker(new boost::asio::io_service::work(mIoService))
	{


		// Determine how many processors are on the system
		//SYSTEM_INFO SystemInfo;
		//GetSystemInfo(&SystemInfo);

		// if they provided 0, the use the number of processors worker threads
		numThreads = (numThreads) ? numThreads : std::thread::hardware_concurrency();
		mWorkerThrds.resize(numThreads);
		u64 i = 0;
		// Create worker threads based on the number of processors available on the
		// system. Create two worker threads for each processor
		for (auto& thrd : mWorkerThrds)
		{
			// Create a server worker thread and pass the completion port to the thread
			thrd = std::thread([&, i]()
			{
				setThreadName("io_Thrd_" + std::to_string(i));
				mIoService.run();

				//std::cout << "io_Thrd_" + std::to_string(i) << " closed" << std::endl;
			});
			++i;
		}
	}

	IOService::~IOService()
	{
		// block until everything has shutdown.
		stop();
	}

	void IOService::stop()
	{


		// Skip if its already shutdown.
		if (mStopped == false)
		{
			mStopped = true;

			// tell all the acceptor threads to stop accepting new connections.
			for (auto& accptr : mAcceptors)
			{
				accptr.stop();
			}

			// delete all of their state.
			mAcceptors.clear();


			mWorker.reset(nullptr);

			// we can now join on them.
			for (auto& thrd : mWorkerThrds)
			{
				thrd.join();
			}
			// clean their state.
			mWorkerThrds.clear();
		}
	}

	void IOService::printErrorMessages(bool v)
	{
		mPrint = v;
	}

	void IOService::receiveOne(ChannelBase* channel)
	{
		////////////////////////////////////////////////////////////////////////////////
		//// THis is within the stand. We have sequential access to the recv queue. ////
		////////////////////////////////////////////////////////////////////////////////

		IOOperation& op = *channel->mRecvQueue.front();

#ifdef CHANNEL_LOGGING
		channel->mLog.push("starting recv #" + ToString(op.mIdx) + ", size = " + ToString(op.size()));
#endif
		if (op.type() == IOOperation::Type::RecvData)
		{
			op.mBuffs[0] = boost::asio::buffer(&channel->mRecvSizeBuff, sizeof(u32));

			std::array<boost::asio::mutable_buffer, 1>tt{ {op.mBuffs[0] } };
			//boost::asio::async_read(*,
			channel->mHandle->async_recv(
				tt,
				[&op, channel, this](const boost::system::error_code& ec, u64 bytesTransfered)
			{
				//////////////////////////////////////////////////////////////////////////
				//// This is *** NOT *** within the stand. Dont touch the recv queue! ////
				//////////////////////////////////////////////////////////////////////////

				 
				if (bytesTransfered != boost::asio::buffer_size(op.mBuffs[0]) || ec)
				{
					auto reason = ("rt error at " LOCATION "\n  ec=" + ec.message() + ". else bytesTransfered != " + std::to_string(boost::asio::buffer_size(op.mBuffs[0])))
						+ "\nThis could be from the other end closing too early or the connection being dropped.\n"
						+ "Channel: " + channel->mLocalName  
						+ ", Session: " + channel->mSession->mName + " " + ToString(channel->mSession->mPort) + " "
						+ ToString(channel->mSession->mMode == SessionMode::Server);


					if (mPrint) std::cout << reason << std::endl;
					channel->setRecvFatalError(reason);
					return;
				}

				std::string msg;

				// We support two types of receives. One where we provide the expected size of the message and one
				// where we allow for variable length messages. op->other will be non null in the resize case and allow
				// us to resize the ChannelBuffer which will hold the data.
					// resize it. This could throw is the channel buffer chooses to.
				if (channel->mRecvSizeBuff != op.size() && op.resize(channel->mRecvSizeBuff) == false)
				{
					msg = std::string() + "The provided buffer does not fit the received message. \n" +
						"   Expected: Container::size() * sizeof(Container::value_type) = " +
						std::to_string(op.size()) + " bytes\n"
						"   Actual: " + std::to_string(channel->mRecvSizeBuff) + " bytes\n\n" +
						"If sizeof(Container::value_type) % Actual != 0, this will throw or ResizableChannelBuffRef<Container>::resize(...) returned false.";
				}
				else
				{
					// set the buffer to point into the channel buffer storage location.
					op.mBuffs[1] = boost::asio::buffer(op.data(), channel->mRecvSizeBuff);
				}



				auto recvMain = [&op, channel, this](const boost::system::error_code& ec, u64 bytesTransfered)
				{
					//////////////////////////////////////////////////////////////////////////
					//// This is *** NOT *** within the stand. Dont touch the recv queue! ////
					//////////////////////////////////////////////////////////////////////////


					if (bytesTransfered != boost::asio::buffer_size(op.mBuffs[1]) || ec)
					{

						auto reason = ("Network error: " + ec.message() + "\nOther end may have crashed. Received incomplete message. at " LOCATION);

						if (mPrint) std::cout << reason << std::endl;
						channel->setRecvFatalError(reason);
						return;
					}

					channel->mTotalRecvData += boost::asio::buffer_size(op.mBuffs[1]);

					//// signal that the recv has completed.
					//if (op.mException)
					//    op.mPromise->set_exception(op.mException);
					//else

					op.mPromise.set_value();

					if (op.mCallback)
					{
						op.mCallback();
					}

					//delete op.mContainer;

					channel->mRecvStrand.dispatch([channel, this, &op]()
					{
						////////////////////////////////////////////////////////////////////////////////
						//// This is within the stand. We have sequential access to the recv queue. ////
						////////////////////////////////////////////////////////////////////////////////
#ifdef CHANNEL_LOGGING
						channel->mLog.push("completed recv #" + ToString(op.mIdx) + ", size = " + ToString(channel->mRecvSizeBuff));
#endif
						//delete channel->mRecvQueue.front();
						channel->mRecvQueue.pop_front();

						// is there more messages to recv?
						bool sendMore = (channel->mRecvQueue.size() != 0);

						if (sendMore)
						{
							receiveOne(channel);
						}
						else if (channel->mRecvStatus == Channel::Status::Stopped)
						{
							channel->mRecvQueueEmptyProm.set_value();
							channel->mRecvQueueEmptyProm = std::promise<void>();
						}
					});
				};



				if (msg.size())
				{
					if (mPrint) std::cout << msg << std::endl;
					channel->setBadRecvErrorState(msg);

					// give the user a chance to give us another location.
					auto e_ptr = std::make_exception_ptr(BadReceiveBufferSize(msg, channel->mRecvSizeBuff, [&, channel, recvMain](u8* dest)
					{
						channel->clearBadRecvErrorState();

						op.mBuffs[1] = boost::asio::buffer(dest, channel->mRecvSizeBuff);

						bool error;
						u64 bytesTransfered;

						std::array<boost::asio::mutable_buffer, 1>tt{ {op.mBuffs[1] } };
						channel->mHandle->recv(tt, error, bytesTransfered);
						auto ec = error ? boost::system::errc::make_error_code(boost::system::errc::io_error) : boost::system::errc::make_error_code(boost::system::errc::success);

						recvMain(ec, bytesTransfered);
					}));

					op.mPromise.set_exception(e_ptr);
					op.mPromise = std::promise<void>();
				}
				else
				{
					std::array<boost::asio::mutable_buffer, 1>tt{ {op.mBuffs[1] } };
					channel->mHandle->async_recv(tt, recvMain);

					//boost::asio::async_read(*channel->mHandle,
					//    std::array<boost::asio::mutable_buffer, 1>{ op.mBuffs[1] }, recvMain);
				}


			});
		}
		else if (op.type() == IOOperation::Type::CloseRecv)
		{
#ifdef CHANNEL_LOGGING
			channel->mLog.push("recvClosed #" + ToString(op.mIdx));
#endif
			//delete channel->mRecvQueue.front();
			channel->mRecvQueue.pop_front();
			channel->mRecvQueueEmptyProm.set_value();
		}
		else
		{
			std::cout << "error, unknown operation " << int(u8(op.type())) << std::endl;
			std::terminate();
		}
		}

	void IOService::sendOne(ChannelBase* socket)
	{
		////////////////////////////////////////////////////////////////////////////////
		//// This is within the stand. We have sequential access to the send queue. ////
		////////////////////////////////////////////////////////////////////////////////

		IOOperation& op = *socket->mSendQueue.front();

#ifdef CHANNEL_LOGGING
		socket->mLog.push("starting send #" + ToString(op.mIdx) + ", size = " + ToString(op.size()));
#endif

		if (op.type() == IOOperation::Type::SendData)
		{
			socket->mSendSizeBuff = u32(op.size());
			op.mBuffs[0] = boost::asio::buffer(&socket->mSendSizeBuff, sizeof(u32));

			socket->mHandle->async_send(op.mBuffs, [&op, socket, this](boost::system::error_code ec, u64 bytesTransferred)
				//boost::asio::async_write(
			{
				//////////////////////////////////////////////////////////////////////////
				//// This is *** NOT *** within the stand. Dont touch the send queue! ////
				//////////////////////////////////////////////////////////////////////////


				if (ec)
				{
					auto reason = std::string("network send error: ") + ec.message() + "\n at  " + LOCATION;
					if (mPrint) std::cout << reason << std::endl;

					socket->setSendFatalError(reason);
					return;
				}

				// lets delete the other pointer as its either nullptr or a buffer that was allocated
				//delete (ChannelBuffer*)op.mOther;

				// make sure all the data sent. If this fails, look up whether WSASend guarantees that all the data in the buffers will be send.
				if (bytesTransferred !=
					boost::asio::buffer_size(op.mBuffs[0]) + boost::asio::buffer_size(op.mBuffs[1]))
				{
					auto reason = std::string("failed to send all data. Expected to send ")
						+ ToString(boost::asio::buffer_size(op.mBuffs[0]) + boost::asio::buffer_size(op.mBuffs[1]))
						+ " bytes but transfered " + ToString(bytesTransferred) + "\n"
						+ "  at  " + LOCATION;

					if (mPrint) std::cout << reason << std::endl;

					socket->setSendFatalError(reason);
					return;
				}

				socket->mOutstandingSendData -= socket->mSendSizeBuff;

				// if this was a synchronous send, fulfill the promise that the message was sent.
				op.mPromise.set_value();

				// if they provided a callback, execute it.
				if (op.mCallback)
				{
					op.mCallback();
				}

				//delete op.mContainer;

				socket->mSendStrand.dispatch([&op, socket, this]()
				{
					////////////////////////////////////////////////////////////////////////////////
					//// This is within the stand. We have sequential access to the send queue. ////
					////////////////////////////////////////////////////////////////////////////////
#ifdef CHANNEL_LOGGING
					socket->mLog.push("completed send #" + ToString(op.mIdx) + ", size = " + ToString(socket->mSendSizeBuff));
#endif
					//delete socket->mSendQueue.front();
					socket->mSendQueue.pop_front();

					// Do we have more messages to be sent?
					auto sendMore = socket->mSendQueue.size();


					if (sendMore)
					{
						sendOne(socket);
					}
					else if (socket->mSendStatus == Channel::Status::Stopped)
					{
						socket->mSendQueueEmptyProm.set_value();
						socket->mSendQueueEmptyProm = std::promise<void>();
					}
				});
			});

		}
		else if (op.type() == IOOperation::Type::CloseSend)
		{
			// This is a special case which may happen if the channel calls stop()
			// with async sends still queued up, we will get here after they get completes. fulfill the
			// promise that all async send operations have been completed.
#ifdef CHANNEL_LOGGING
			socket->mLog.push("sendClosed #" + ToString(op.mIdx));
#endif
			//delete socket->mSendQueue.front();
			socket->mSendQueue.pop_front();
			socket->mSendQueueEmptyProm.set_value();
		}
		else
		{
			std::cout << "error, unknown operation " << std::endl;
			std::terminate();
		}
		}

	void IOService::dispatch(ChannelBase* socket, std::unique_ptr<IOOperation>op)
	{
#ifdef CHANNEL_LOGGING
		op->mIdx = socket->mOpIdx++;
#endif

		switch (op->type())
		{
		case IOOperation::Type::RecvData:
		case IOOperation::Type::CloseRecv:
		{
			// boost complains if generalized move symantics are used with a post(...) callback
			auto opPtr = op.release();

			// a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
			socket->mRecvStrand.post([this, socket, opPtr]()
			{
				std::unique_ptr<IOOperation>op(opPtr);

				// check to see if we should kick off a new set of recv operations. If the size >= 1, then there
				// is already a set of recv operations that will kick off the newly queued recv when its turn comes around.
				bool startRecving = (socket->mRecvQueue.size() == 0) && (socket->mRecvSocketSet || op->type() == IOOperation::Type::CloseRecv);

#ifdef CHANNEL_LOGGING
				if (op->type() == IOOperation::Type::RecvData)
					socket->mLog.push("queuing recv #" + ToString(op->mIdx) + ", size = " + ToString(op->size()) + ", start = " + ToString(startRecving));
				else
					socket->mLog.push("queuing recvClosing #" + ToString(op->mIdx) + ", start = " + ToString(startRecving));
#endif

				// the queue must be guarded from concurrent access, so add the op within the strand
				// queue up the operation.
				socket->mRecvQueue.emplace_back(std::move(op));
				if (startRecving)
				{
					// ok, so there isn't any recv operations currently underway. Lets kick off the first one. Subsequent recvs
					// will be kicked off at the completion of this operation.
					receiveOne(socket);
				}
			});
		}
		break;
		case IOOperation::Type::SendData:
		case IOOperation::Type::CloseSend:
		{
			//std::cout << " dis " << (op->type() == IOOperation::Type::SendData ? "SendData" : "CloseSend") << std::endl;

			// boost complains if generalized move symantics are used with a post(...) callback
			auto opPtr = op.release();
			// a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
			socket->mSendStrand.post([this, socket, opPtr]()
			{
				std::unique_ptr<IOOperation>op(opPtr);
				// the queue must be guarded from concurrent access, so add the op within the strand


				socket->mTotalSentData += op->size();
				socket->mOutstandingSendData += op->size();
				socket->mMaxOutstandingSendData = std::max((u64)socket->mOutstandingSendData, (u64)socket->mMaxOutstandingSendData);

				// check to see if we should kick off a new set of send operations. If the size >= 1, then there
				// is already a set of send operations that will kick off the newly queued send when its turn comes around.
				auto startSending = (socket->mSendQueue.size() == 0) && (socket->mSendSocketSet || op->type() == IOOperation::Type::CloseSend);

#ifdef CHANNEL_LOGGING
				if (op->type() == IOOperation::Type::SendData)
					socket->mLog.push("queuing send #" + ToString(op->mIdx) +
						", size = " + ToString(op->size()) + ", start = " + ToString(startSending));
				else
					socket->mLog.push("queuing sendClosing #" + ToString(op->mIdx) + ", start = " + ToString(startSending));
#endif
				// add the operation to the queue.
				socket->mSendQueue.emplace_back(std::move(op));

				if (startSending)
				{

					// ok, so there isn't any send operations currently underway. Lets kick off the first one. Subsequent sends
					// will be kicked off at the completion of this operation.
					sendOne(socket);

			}
		});
		}
		break;
		default:

			std::cout << ("unknown IOOperation::Type") << std::endl;
			std::terminate();
			break;
	}
	}


	void IOService::aquireAcceptor(std::shared_ptr<SessionBase>& session)
	{
		std::promise<std::list<Acceptor>::iterator> p;
		std::future<std::list<Acceptor>::iterator> f = p.get_future();

		mStrand.dispatch([&]()
		{
			// see if there already exists an acceptor that this endpoint can use.
			auto acceptorIter = std::find_if(
				mAcceptors.begin(),
				mAcceptors.end(), [&](const Acceptor& acptr)
			{
				return acptr.mPort == session->mPort;
			});

			if (acceptorIter == mAcceptors.end())
			{
				// an acceptor does not exist for this port. Lets create one.
				mAcceptors.emplace_back(*this);
				acceptorIter = mAcceptors.end(); --acceptorIter;
				acceptorIter->mPort = session->mPort;

				//std::cout << "creating acceptor on " + ToString(session->mPort) << std::endl;
			}

			p.set_value(acceptorIter);
		});
		auto acceptorIter = f.get();
		acceptorIter->subscribe(session);

	}

	void IOService::startSocket(ChannelBase * chl, std::unique_ptr<BoostSocketInterface> socket)
	{

		chl->mHandle = std::move(socket);
		// a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
		chl->mRecvStrand.post([this, chl]()
		{


#ifdef CHANNEL_LOGGING
			chl->mLog.push("initRecv , start = " + ToString(chl->mRecvQueue.size()));
#endif

			// check to see if we should kick off a new set of recv operations. Since we are just now
			// starting the channel, its possible that the async connect call returned and the caller scheduled a receive
			// operation. But since the channel handshake just finished, those operations didn't start. So if
			// the queue has anything in it, we should actually start the operation now...

			if (chl->mRecvQueue.size())
			{
				// ok, so there isn't any recv operations currently underway. Lets kick off the first one. Subsequent recvs
				// will be kicked off at the completion of this operation.
				receiveOne(chl);
			}


			chl->mRecvSocketSet = true;

			auto ii = ++chl->mOpenCount;
			if (ii == 2)
				chl->mOpenProm.set_value();
		});


		// a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
		chl->mSendStrand.post([this, chl]()
		{
			// the queue must be guarded from concurrent access, so add the op within the strand

			auto start = chl->mSendQueue.size();
#ifdef CHANNEL_LOGGING
			chl->mLog.push("initSend , start = " + ToString(start));
#endif
			// check to see if we should kick off a new set of send operations. Since we are just now
			// starting the channel, its possible that the async connect call returned and the caller scheduled a send
			// operation. But since the channel handshake just finished, those operations didn't start. So if
			// the queue has anything in it, we should actually start the operation now...

			if (start)
			{
				// ok, so there isn't any send operations currently underway. Lets kick off the first one. Subsequent sends
				// will be kicked off at the completion of this operation.
				sendOne(chl);
			}

			chl->mSendSocketSet = true;

			auto ii = ++chl->mOpenCount;
			if (ii == 2)
				chl->mOpenProm.set_value();

		});
	}


	void details::SessionGroup::add(NamedSocket s, Acceptor* a)
	{
		auto iter = std::find_if(mChannels.begin(), mChannels.end(),
			[&](const std::shared_ptr<ChannelBase>& chl)
		{
			return chl->mLocalName == s.mLocalName &&
				chl->mRemoteName == s.mRemoteName;
		});

		if (iter != mChannels.end())
		{
			a->mIOService.startSocket(iter->get(), std::move(s.mSocket));
			mChannels.erase(iter);
		}
		else
		{
			mSockets.emplace_back(std::move(s));
		}
	}

	void details::SessionGroup::add(const std::shared_ptr<ChannelBase>& chl, Acceptor* a)
	{
		auto iter = std::find_if(mSockets.begin(), mSockets.end(),
			[&](const NamedSocket& s)
		{
			return chl->mLocalName == s.mLocalName &&
				chl->mRemoteName == s.mRemoteName;
		});

		if (iter != mSockets.end())
		{
			a->mIOService.startSocket(chl.get(), std::move(iter->mSocket));
			mSockets.erase(iter);
		}
		else
		{
			mChannels.emplace_back(chl);
		}
	}

	bool details::SessionGroup::hasMatchingChannel(const NamedSocket & s) const
	{
		return mChannels.end() != std::find_if(mChannels.begin(), mChannels.end(),
			[&](const std::shared_ptr<ChannelBase>& chl)
		{
			return chl->mLocalName == s.mLocalName &&
				chl->mRemoteName == s.mRemoteName;
		});
	}

	bool details::SocketGroup::hasMatchingSocket(const std::shared_ptr<ChannelBase>& chl) const
	{
		return mSockets.end() != std::find_if(mSockets.begin(), mSockets.end(),
			[&](const NamedSocket& s)
		{
			return chl->mLocalName == s.mLocalName &&
				chl->mRemoteName == s.mRemoteName;
		});
	}

	void details::SessionGroup::merge(details::SocketGroup& merge, Acceptor* a)
	{
		if (mSockets.size())
			throw std::runtime_error(LOCATION);

		for (auto& s : merge.mSockets) add(std::move(s), a);
		merge.mSockets.clear();

		auto session = mBase.lock();
		if (session)
		{
			if (merge.mSessionID == 0 ||
				session->mName != merge.mName ||
				session->mSessionID)
				throw std::runtime_error(LOCATION);

			session->mName = std::move(merge.mName);
			session->mSessionID = merge.mSessionID;
		}
	}


	}
