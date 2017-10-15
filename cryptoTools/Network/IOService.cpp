#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Finally.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Network/Endpoint.h>
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
		mSocketChannelPairsRemovedFuture(mSocketChannelPairsRemovedProm.get_future()),
		mIOService(ioService),
		mHandle(ioService.mIoService),
		mStopped(false),
		mPort(0)
	{
	}

	Acceptor::~Acceptor()
	{
		stop();
	}

	void Acceptor::bind(u32 port, std::string ip)
	{
		auto pStr = std::to_string(port);
		mPort = port;

		boost::asio::ip::tcp::resolver resolver(mIOService.mIoService);
		boost::asio::ip::tcp::resolver::query
			query(ip, pStr);

		boost::system::error_code ec;
		auto addrIter = resolver.resolve(query, ec);

		if (ec)
		{
			std::cout << "network address resolve error: " << ec.message() << std::endl;

			throw std::runtime_error(ec.message());
		}

		mAddress = *addrIter;

		mHandle.open(mAddress.protocol());
		mHandle.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

		mHandle.bind(mAddress, ec);

		if (mAddress.port() != port)
			throw std::runtime_error("rt error at " LOCATION);

		if (ec)
		{
			std::cout << "network address bind error: " << ec.message() << std::endl;

			throw std::runtime_error(ec.message());
		}


		//std::promise<void> mStoppedListeningPromise, mSocketChannelPairsRemovedProm;
		//std::future<void> mStoppedListeningFuture, mSocketChannelPairsRemovedFuture;
		mStoppedListeningFuture = (mStoppedListeningPromise.get_future());
		mHandle.listen(boost::asio::socket_base::max_connections);
	}

	void Acceptor::start()
	{
		if (stopped() == false)
		{


			BoostSocketInterface* newSocket = new BoostSocketInterface(mIOService.mIoService);
			mHandle.async_accept(newSocket->mSock, [newSocket, this](const boost::system::error_code& ec)
			{
				start();

				if (!ec)
				{
					boost::asio::ip::tcp::no_delay option(true);
					newSocket->mSock.set_option(option);
					auto buff = new std::string(sizeof(u32), '\0');

					newSocket->mSock.async_receive(boost::asio::buffer((char*)buff->data(), buff->size()),
						[newSocket, buff, this](const boost::system::error_code& ec2, u64 bytesTransferred)
					{
						if (!ec2 && bytesTransferred == 4)
						{
							auto size = *(u32*)buff->data();
							buff->resize(size);

							newSocket->mSock.async_receive(boost::asio::buffer((char*)buff->data(), buff->size()),
								[newSocket, buff, this](const boost::system::error_code& ec3, u64 bytesTransferred2)
							{
								if (!ec3 && bytesTransferred2 == buff->size())
								{
									asyncSetSocket(std::move(*buff), std::move(std::unique_ptr<BoostSocketInterface>(newSocket)));
								}
								else
								{
									std::cout << "async_accept error, failed to receive first header on connection handshake."
										<< " Other party may have closed the connection. "
										<< ((ec3 != 0) ? "Error code:" + ec3.message() : " received " + ToString(bytesTransferred2) + " / 4 bytes") << "  " << LOCATION << std::endl;

									delete newSocket;
								}

								delete buff;
							});

						}
						else
						{
							std::cout << "async_accept error, failed to receive first header on connection handshake."
								<< " Other party may have closed the connection. "
								<< ((ec2 != 0) ? "Error code:" + ec2.message() : " received " + ToString(bytesTransferred) + " / 4 bytes") << "  " << LOCATION << std::endl;

							delete newSocket;
							delete buff;
						}

					});
				}
				else
				{
					//std::cout << IoStream::lock<< "async_accept failed with error_code:" << ec.message() << std::endl << IoStream::unlock;
					delete newSocket;
				}
			});
		}
		else
		{
			mStoppedListeningPromise.set_value();
		}
	}

	void Acceptor::stop()
	{
		//std::cout << "\n#################################### acceptor stop ################################" << std::endl;

		if (mStopped == false)
		{

			{
				std::unique_lock<std::mutex> lock(mSocketChannelPairsMtx);
				mStopped = true;

				if (hasPendingsChannels() == false)
					mSocketChannelPairsRemovedProm.set_value();
			}

			if (mSocketChannelPairsRemovedFuture.valid())
				mSocketChannelPairsRemovedFuture.get();


			mHandle.close();

			if (mStoppedListeningFuture.valid())
				mStoppedListeningFuture.get();


			removePendingSockets();

		}

	}

	bool Acceptor::stopped() const
	{
		return mStopped;
	}
	//std::atomic<int> ccc(0);

	void Acceptor::asyncGetSocket(std::shared_ptr<ChannelBase> chl)
	{
		std::unique_lock<std::mutex> lock(mSocketChannelPairsMtx);

		auto& endpointName = chl->mEndpoint->mName;
		auto& localName = chl->mLocalName;
		auto& remoteName = chl->mRemoteName;

		if (endpointName == "")
		{
			// anonymous Endpoint. Lets try and match the channel name with
			// the first socket name.

			auto anIter = std::find_if(mAnonymousClientEps.begin(), mAnonymousClientEps.end(),
				[&](const EndpointGroup& epg) {
				return epg.mSockets.front().mLocalName == localName &&
					epg.mSockets.front().mRemoteName == remoteName;
			});

			// See if we can find a socket that matches.
			if (anIter != mAnonymousClientEps.end())
			{
				auto& group = *anIter;
				auto& sockets = group.mSockets;
				auto& socket = sockets.front();

				// we found a match. Lets rename this endpoint to match the 
				// client's random name
				endpointName = group.mName;
				group.mBase = chl->mEndpoint;
				//group.mComment += " .normal case. channel found anGroup. " + std::to_string(ccc++) + " ";
					
				// start the socket.
				mIOService.startSocket(chl.get(), std::move(socket.mSocket));
				group.mSuccessfulConnections++;
				sockets.pop_front();

				// move the endpoint group to the named list
				mEndpointGroups.emplace(endpointName, std::move(group));

				// remove the old copy
				mAnonymousClientEps.erase(anIter);

				// check if we are all done
				if (stopped() && isEmpty())
					mSocketChannelPairsRemovedProm.set_value();
			}
			else
			{
				// The client has not connected with a correctly named
				// channel with an anonymous endpoint. Lets check if
				// we have created a group to store these channel.
				anIter = std::find_if(mAnonymousServerEps.begin(), mAnonymousServerEps.end(),
					[&](const EndpointGroup& epg) {
					return epg.mBase == chl->mEndpoint;
				});

				if (anIter == mAnonymousServerEps.end())
				{
					// This is the first channel for this endpoint.
					// Lets create a group to store the channel in
					// until it has a connecting socket.
					mAnonymousServerEps.emplace_back();
					anIter = mAnonymousServerEps.end();
					--anIter;

					anIter->mBase = chl->mEndpoint;
				}

				// store this channel in this group until
				// there is a connecting socket.
				auto& group = *anIter;
				group.mChannels.emplace_back(chl);
				//group.mComment += "missing socket. " + std::to_string(ccc++) + " ";
			}
		}
		else
		{
			// check if the corresponding group exists
			auto iter = mEndpointGroups.find(endpointName);
			if (iter == mEndpointGroups.end())
			{
				// no group exists. This is the first channel for the endpoint and
				// the client has yet to connect a socket with this endpoint name. 
				// Create a new group to store the channel in.
				iter = mEndpointGroups.emplace(endpointName, EndpointGroup()).first;
				iter->second.mName = endpointName;
				iter->second.mBase = chl->mEndpoint;
			}

			auto& group = iter->second;

			// check if there is a socket that matches this channel's name
			auto sockIter = std::find_if(group.mSockets.begin(), group.mSockets.end(),
				[&](const EndpointGroup::NamedSocket& sock)
			{
				return sock.mLocalName == localName &&
					sock.mRemoteName == remoteName;
			});

			if (sockIter != group.mSockets.end())
			{
				// we have found a match. Lets connect the socket to the channel
				mIOService.startSocket(chl.get(), std::move(sockIter->mSocket));
				group.mSuccessfulConnections++;
				group.mSockets.erase(sockIter);

				// check if we are all done
				if (stopped() && isEmpty())
					mSocketChannelPairsRemovedProm.set_value();
			}
			else
			{
				// no match was found. Lets store the channel in the group.
				group.mChannels.emplace_back(chl);
			}
		}
	}

	bool Acceptor::isEmpty() const
	{
		for (auto& ep : mAnonymousClientEps)
			if (ep.isEmpty() == false)
				return false;
		for (auto& ep : mAnonymousServerEps)
			if (ep.isEmpty() == false)
				return false;
		for (auto& ep : mEndpointGroups)
			if (ep.second.isEmpty() == false)
				return false;

		return true;
	}

	bool Acceptor::hasPendingsChannels() const
	{
		for (auto& ep : mAnonymousClientEps)
			if (ep.hasPendingChannels())
				return true;
		for (auto& ep : mAnonymousServerEps)
			if (ep.hasPendingChannels())
				return true;
		for (auto& ep : mEndpointGroups)
			if (ep.second.hasPendingChannels())
				return true;

		return false;
	}

	void Acceptor::removePendingSockets()
	{
		std::unique_lock<std::mutex> lock(mSocketChannelPairsMtx);

		for (auto& ep : mAnonymousClientEps)
			ep.mSockets.clear();

		for (auto& ep : mAnonymousServerEps)
			ep.mSockets.clear();

		for (auto& ep : mEndpointGroups)
			ep.second.mSockets.clear();
	}

	//void Acceptor::removeEndpoint(const EndpointBase* ep, const std::optional<std::chrono::milliseconds>& waitTime)
	//{
	//	//auto anIter = std::find_if(mAnonymousServerEps.begin(), mAnonymousServerEps.end(),
	//	//	[&](const EndpointGroup& epg) {
	//	//	return epg.mBase.get() == ep;
	//	//});
	//	//if (anIter != mAnonymousServerEps.end())
	//	//{
	//	//	anIter->waitForChannels(mSocketChannelPairsMtx, waitTime);
	//	//	//std::lock_guard<std::mutex> lock(mSocketChannelPairsMtx);
	//	//	//anIter->
	//	//}
	//	//else
	//	//{
	//	//	auto iter = mEndpointGroups.find(ep->mName);
	//	//	if (iter != mEndpointGroups.end())
	//	//	{
	//	//		iter->second.waitForChannels(mSocketChannelPairsMtx, waitTime);
	//	//	}
	//	//}
	//}


	//void Acceptor::EndpointGroup::waitForChannels(std::mutex & mtx, const std::optional<std::chrono::milliseconds>& waitTime)
	//{
	//	bool wait = false;
	//	{
	//		std::lock_guard<std::mutex> lock(mtx);
	//		if (mChannels.size())
	//		{
	//			wait = true;
	//			mFuture = mProm.get_future();
	//		}
	//	}

	//	if (wait)
	//	{
	//		if (waitTime)
	//		{
	//			auto status = mFuture.wait_for(*waitTime);
	//			if (status == std::future_status::ready)
	//				mFuture.get();
	//		}
	//		else
	//			mFuture.get();
	//	}
	//}


	void Acceptor::asyncSetSocket(
		std::string name,
		std::unique_ptr<BoostSocketInterface> sock)
	{

		std::unique_lock<std::mutex> lock(mSocketChannelPairsMtx);

		auto names = split(name, '`');

		// check for the special case that this is a
		// randomly named endpoint, i.e.  the user provided
		// no endpoint name.
		bool anonymousEp = false;
		if (names.size() == 4 && names[3] == "#")
		{
			anonymousEp = true;
			names.pop_back();
		}


		if (names.size() == 3)
		{
			auto& endpointName = names[0];
			auto& remoteName = names[1];
			auto& localName = names[2];

			if (anonymousEp)
			{

				// See if there exists an anonymous endpoints
				// for which the channel name matches. If so rename
				// the endpoint with the name provided by the client
				// and forward the new sock onto the existing channel.
				auto anIter = std::find_if(mAnonymousServerEps.begin(), mAnonymousServerEps.end(),
					[&](const EndpointGroup& epg) {
					return epg.mChannels.size() &&
						epg.mChannels.front()->mLocalName == localName &&
						epg.mChannels.front()->mRemoteName == remoteName;
				});

				// SPECIAL CASE: check if by some random chance other (named) connections have been
				// made ahead of this one with the proposed endpoint name. This can happen 
				// if messages are delayed/reordered over the network...
				auto epIter = mEndpointGroups.find(endpointName);
				if (epIter != mEndpointGroups.end())
				{
					auto& namedGroup = epIter->second;
					if (namedGroup.mSuccessfulConnections || namedGroup.mChannels.size())
					{
						// this should not happen. The random name proposed
						// by the client has already been used... As such we
						// simply give up and drop the connection.
						std::cout << "connection name:" << name
							<< " already in use. Dropping the connection." << std::endl;
						return;
					}

					// ok, we have this named group which has no successful
					// connection made on this side. That is, no channels
					// have used sockets from this group. 

					// It is possible that the user on this side has some 
					// anonymous group on this side with sockets that can be 
					// matched. Lets try and find such an anonymous group
					if (anIter != mAnonymousServerEps.end())
					{
						// we found such a group. This means that the client has
						// established several sockets with the server. These are held in 
						// namedGroup. The server has also created several channels
						// with an anonymous endpoint. This lastest socket is a match
						// to this named endpoint and has a socket that matches the 
// anonymous group. We therefore merge these two groups together.

						auto& anGroup = *anIter;
						auto& chl = anGroup.mChannels.front();

						// start with the current sock that matches the first channel.
						mIOService.startSocket(chl.get(), std::move(sock));
						namedGroup.mSuccessfulConnections++;
						anGroup.mChannels.pop_front();

						// ok, we need to merge these groups and complete
						// any connections that we can. For each channel,
						// lets look for a matching socket.
						auto chlIter = anGroup.mChannels.begin();
						while (chlIter != anGroup.mChannels.end())
						{
							auto& chl2 = *chlIter;

							// see if there exists a socket with chl2's name.
							auto sockIter = std::find_if(namedGroup.mSockets.begin(), namedGroup.mSockets.end(),
								[&](const Acceptor::EndpointGroup::NamedSocket& sock2) {
								return sock2.mLocalName == chl2->mLocalName &&
									sock2.mRemoteName == chl2->mRemoteName;
							});

							if (sockIter != namedGroup.mSockets.end())
							{
								// we have a match, start the socket
								mIOService.startSocket(chl2.get(), std::move(sockIter->mSocket));
								namedGroup.mSuccessfulConnections++;

								// remove the channel and socket
								namedGroup.mSockets.erase(sockIter);
								chlIter = anGroup.mChannels.erase(chlIter);
							}
							else
							{
								// try the next channel
								++chlIter;
							}
						}

						// All the channels and sockets remaining did no match.
						// Lets move the channels into the named group.
						namedGroup.mChannels = std::move(anGroup.mChannels);
						namedGroup.mBase = anGroup.mBase;
						namedGroup.mBase->mName = namedGroup.mName;
						//namedGroup.mComment += "special case merge. " + std::to_string(ccc++) + " ";

						// make sure everything went correctly. Should never throw..
						if (anGroup.isEmpty() == false)
							throw std::runtime_error(LOCATION);

						// removed the anGroup
						mAnonymousServerEps.erase(anIter);
						return;
					}
				}


				// COMMON CASE: this is the first connection for the anonymous 
				// endpoint and we simply need to check if the server has created
				// the corresponding endpoint group or if we need to make one.
				if (anIter != mAnonymousServerEps.end())
				{
					// The server has already created a matching endpoint group.
					auto& group = *anIter;
					auto& chl = group.mChannels.front();

					// assign the group and endpoint a name
					group.mName = endpointName;
					group.mBase->mName = endpointName;
					//group.mComment += "normal case. socket found anGroupServer. " + std::to_string(ccc++);

					// start the socket
					mIOService.startSocket(chl.get(), std::move(sock));
					group.mSuccessfulConnections++;

					// removed the connected channel
					group.mChannels.pop_front();

					// move the group into the list of named endpoints
					mEndpointGroups.emplace(endpointName, std::move(*anIter));
					
					// remove this endpoint from the mAnonymousEps list
					mAnonymousServerEps.erase(anIter);

					// check if we are all done
					if (stopped() && isEmpty())
						mSocketChannelPairsRemovedProm.set_value();
				}
				else
				{
					// We failed to find an endpoint with a correctly named channel.
					// As such we will create a new endpoint group and store the socket
					// there. When/if the corresponding channel is created, that channel
					// will be able to find the socket here.

					auto iter = std::find_if(mAnonymousClientEps.begin(), mAnonymousClientEps.end(),
						[&](const EndpointGroup& epg) {
						return epg.mName == endpointName;
					});

					if (iter != mAnonymousClientEps.end())
					{
						std::cout << "duplicate anonymous endpoint name: " << endpointName << "\nDropping connnection." << std::endl;
						return;
					}

					mAnonymousClientEps.emplace_back();
					auto& group = mAnonymousClientEps.back();
					group.mName = endpointName;
					group.mSockets.emplace_back();
					group.mSockets.back().mRemoteName = remoteName;
					group.mSockets.back().mLocalName = localName;
					group.mSockets.back().mSocket = std::move(sock);
				}

			}
			else
			{
				// Here the client has provided an explicit endpoint Name.
				// We need to check if there is a channel under that endpoint 
				// name that is waiting for of the socket. If so we forward  
				// the socket onto that channel. Otherwise we need to create 
				// a new endpoint group and store the socket there.

				auto iter = mEndpointGroups.find(endpointName);

				if (iter == mEndpointGroups.end())
				{
					// The endpoint has not been created/used yet. Lets create a 
					// new EndpointGroup and store the socket there. A channel
					// will (maybe) come along later and aquire the socket.
					iter = mEndpointGroups.insert({ endpointName, EndpointGroup() }).first;
					iter->second.mName = endpointName;
				}

				// Now check if there is a channel looking for this socket.
				auto& group = iter->second;

				auto chlIter = std::find_if(group.mChannels.begin(), group.mChannels.end(),
					[&](const std::shared_ptr<ChannelBase>& chl) {
					return  chl->mLocalName == localName &&
						chl->mRemoteName == remoteName;
				});
				if (chlIter != group.mChannels.end())
				{
					auto& chlPtr = *chlIter;
					// start the socket.
					mIOService.startSocket(chlPtr.get(), std::move(sock));
					group.mSuccessfulConnections++;

					// remove the channel from the list of un-connected channels
					group.mChannels.erase(chlIter);

					// check if this accepter has completed all its work. If so and 
					// stop has been called, make the all connections have been made
					if (stopped() && isEmpty())
						mSocketChannelPairsRemovedProm.set_value();
				}
				else
				{
					// If we have made it here the no channel has required this socket.
					// In the mean time we will store the socket in this group.
					group.mSockets.emplace_back();
					group.mSockets.back().mRemoteName = remoteName;
					group.mSockets.back().mLocalName = localName;
					group.mSockets.back().mSocket = std::move(sock);
				}
			}
		}
		else
		{
			std::cout << "bad channel name: " << name << std::endl
				<< "Dropping the connection" << std::endl;;
		}
	}

	//void Acceptor::remove(
	//	std::string endpointName,
	//	std::string localChannelName,
	//	std::string remoteChannelName)
	//{
	//	std::string tag = endpointName + ":" + localChannelName + ":" + remoteChannelName;

	//	{
	//		//mSocketChannelPairsMtx.lock();
	//		std::unique_lock<std::mutex> lock(mSocketChannelPairsMtx);
	//		auto iter = mSocketChannelPairs.find(tag);

	//		if (iter != mSocketChannelPairs.end())
	//		{

	//			if (iter->second.first)
	//			{
	//				iter->second.first->close();
	//				delete iter->second.first;

	//				//std::cout << "erase2   " << iter->first << std::endl;
	//				mSocketChannelPairs.erase(iter);


	//				if (mStopped == true && mSocketChannelPairs.size() == 0)
	//				{
	//					mSocketChannelPairsRemovedProm.set_value();
	//				}
	//			}
	//			else
	//			{
	//				iter->second.second = nullptr;
	//			}
	//		}
	//		//mSocketChannelPairsMtx.unlock();
	//	}
	//}


	extern void split(const std::string &s, char delim, std::vector<std::string> &elems);
	extern std::vector<std::string> split(const std::string &s, char delim);

	IOService::IOService(u64 numThreads)
		:
		mIoService(),
		mWorker(new boost::asio::io_service::work(mIoService)),
		mStopped(false),
		mPrint(true)
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
		//WaitCallback wait();
		//boost::asio::deadline_timer timer(mIoService, boost::posix_time::seconds(5));
		//timer.async_wait([&](boost::system::error_code ec) {

		//    if (!ec)
		//    {
		//        std::cerr << "waiting for endpoint/channel to close " << std::endl;;
		//    }
		//});


		std::lock_guard<std::mutex> lock(mMtx);

		// Skip if its already shutdown.
		if (mStopped == false)
		{
			mWorker.reset(nullptr);
			mStopped = true;

			// tell all the acceptor threads to stop accepting new connections.
			for (auto& accptr : mAcceptors)
			{
				accptr.stop();
			}

			// delete all of their state.
			mAcceptors.clear();

			// we can now join on them.
			for (auto& thrd : mWorkerThrds)
			{
				thrd.join();
			}

			// clean their state.
			mWorkerThrds.clear();
			// close the completion port since no more IO operations will be queued.

		}

		//timer.cancel();
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

			std::array<boost::asio::mutable_buffer, 1>tt{ op.mBuffs[0] };
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
						+ "\nThis could be from the other end closing too early or the connection being dropped.";

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

						std::array<boost::asio::mutable_buffer, 1>tt{ op.mBuffs[1] };
						channel->mHandle->recv(tt, error, bytesTransfered);
						auto ec = error ? boost::system::errc::make_error_code(boost::system::errc::io_error) : boost::system::errc::make_error_code(boost::system::errc::success);

						recvMain(ec, bytesTransfered);
					}));

					op.mPromise.set_exception(e_ptr);
					op.mPromise = std::promise<void>();
				}
				else
				{
					std::array<boost::asio::mutable_buffer, 1>tt{ op.mBuffs[1] };
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


	Acceptor* IOService::getAcceptor(std::string ip, i32 port)
	{
		std::lock_guard<std::mutex> lock(mMtx);

		// see if there already exists an acceptor that this endpoint can use.
		auto acceptorIter = std::find_if(
			mAcceptors.begin(),
			mAcceptors.end(), [&](const Acceptor& acptr)
		{
			return acptr.mPort == port;
		});

		if (acceptorIter == mAcceptors.end())
		{
			// an acceptor does not exist for this port. Lets create one.
			mAcceptors.emplace_back(*this);
			auto& acceptor = mAcceptors.back();

			try {

				acceptor.bind(port, ip);
			}
			catch (...)
			{
				mAcceptors.pop_back();
				throw;
			}

			acceptor.start();
			return &acceptor;
		}
		else
		{
			// there is an acceptor already accepting sockets on the desired port. So return it.
			return &(*acceptorIter);
		}
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




	void Acceptor::EndpointGroup::print()
	{
		
		std::cout << "name: " << mName << " " << mBase.get() << std::endl;


		for (auto& b : mChannels)
		{
			std::cout << "   chl: " << b->mLocalName << std::endl;
		}

		for (auto& b : mSockets)
		{
			std::cout << "   sock:" << b.mLocalName << std::endl;
		}
	}

}
