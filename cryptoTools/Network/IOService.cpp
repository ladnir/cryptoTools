#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Defines.h>
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
									auto names = split(*buff, '`');
									if (buff->back() == '`' && names.size() == 2) names.emplace_back("");
									asyncSetSocket(names[0], names[2], names[1], newSocket);
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

				if (mSocketChannelPairs.size() == 0)
					mSocketChannelPairsRemovedProm.set_value();

			}

			if (mSocketChannelPairsRemovedFuture.valid())
				mSocketChannelPairsRemovedFuture.get();

			mHandle.close();

			if (mStoppedListeningFuture.valid())
				mStoppedListeningFuture.get();
		}

	}

	bool Acceptor::stopped() const
	{
		return mStopped;
	}

	void Acceptor::asyncGetSocket(ChannelBase & chl)
	{
		std::string tag = chl.mEndpoint->getName() + ":" + chl.mLocalName + ":" + chl.mRemoteName;

		{
			std::unique_lock<std::mutex> lock(mSocketChannelPairsMtx);
			//mSocketChannelPairsMtx.lock();

			auto iter = mSocketChannelPairs.find(tag);

			if (iter == mSocketChannelPairs.end())
			{

				//std::cout << IoStream::lock << "asyncGetSocket waiting on socket " << tag << std::endl << IoStream::unlock;
				mSocketChannelPairs.emplace(tag, std::pair<BoostSocketInterface*, ChannelBase*>(nullptr, &chl));
			}
			else
			{
				// std::cout <<IoStream::lock << "asyncGetSocket aquired socket " << tag << std::endl << IoStream::unlock;
				if (iter->second.first == nullptr)
				{
					std::cout << "netowrking error: channel " << tag << " already exists.";
					std::terminate();
				}

				chl.mHandle.reset(iter->second.first);

				chl.mRecvSocketSet = true;
				chl.mSendSocketSet = true;
				chl.mOpenProm.set_value();

				//std::cout << "erase1   " << iter->first << std::endl;
				mSocketChannelPairs.erase(iter);


				if (mStopped == true && mSocketChannelPairs.size() == 0)
				{
					mSocketChannelPairsRemovedProm.set_value();
				}
			}
			//mSocketChannelPairsMtx.unlock();
		}
	}

	void Acceptor::remove(
		std::string endpointName,
		std::string localChannelName,
		std::string remoteChannelName)
	{
		std::string tag = endpointName + ":" + localChannelName + ":" + remoteChannelName;

		{
			//mSocketChannelPairsMtx.lock();
			std::unique_lock<std::mutex> lock(mSocketChannelPairsMtx);
			auto iter = mSocketChannelPairs.find(tag);

			if (iter != mSocketChannelPairs.end())
			{

				if (iter->second.first)
				{
					iter->second.first->close();
					delete iter->second.first;

					//std::cout << "erase2   " << iter->first << std::endl;
					mSocketChannelPairs.erase(iter);


					if (mStopped == true && mSocketChannelPairs.size() == 0)
					{
						mSocketChannelPairsRemovedProm.set_value();
					}
				}
				else
				{
					iter->second.second = nullptr;
				}
			}
			//mSocketChannelPairsMtx.unlock();
		}
	}


	void Acceptor::asyncSetSocket(
		std::string endpointName,
		std::string localChannelName,
		std::string remoteChannelName,
		BoostSocketInterface* sock)
	{
		std::string tag = endpointName + ":" + localChannelName + ":" + remoteChannelName;

		{
			std::unique_lock<std::mutex> lock(mSocketChannelPairsMtx);
			//mSocketChannelPairsMtx.lock();

			const auto iter = mSocketChannelPairs.find(tag);

			if (iter == mSocketChannelPairs.end())
			{
				//std::cout << "asyncSetSocket created socket " << tag << std::endl;
				mSocketChannelPairs.emplace(tag, std::pair<BoostSocketInterface*, ChannelBase*>(sock, nullptr));
			}
			else
			{

				if (iter->second.second == nullptr)
				{
					boost::system::error_code ec;
					sock->mSock.close(ec);


					if (ec)
					{
						std::cout << ec.message() << std::endl;
					}
				}
				else
				{
					iter->second.second->mHandle.reset(sock);

					mIOService.startSocket(iter->second.second);
				}

				mSocketChannelPairs.erase(iter);


				if (mStopped == true && mSocketChannelPairs.size() == 0)
				{
					mSocketChannelPairsRemovedProm.set_value();
				}
			}
			//mSocketChannelPairsMtx.unlock();
		}

	}
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

            // wait for all the endpoints that use this IO service to finish.
            for (auto future : mEndpointStopFutures)
            {
                future.get();
            }

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


    Acceptor* IOService::getAcceptor(Endpoint& endpoint)
    {

        if (endpoint.isHost())
        {
            std::lock_guard<std::mutex> lock(mMtx);

            // see if there already exists an acceptor that this endpoint can use.
            auto acceptorIter = std::find_if(
                mAcceptors.begin(),
                mAcceptors.end(), [&](const Acceptor& acptr)
            {
                return acptr.mPort == endpoint.port();
            });

            if (acceptorIter == mAcceptors.end())
            {
                // an acceptor does not exist for this port. Lets create one.
                mAcceptors.emplace_back(*this);
                auto& acceptor = mAcceptors.back();


                auto port = endpoint.port();
                auto ip = endpoint.IP();

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
        else
        {
            // client end points dont need acceptors since they initiate the connection.
            throw std::runtime_error("rt error at " LOCATION);
        }
    }

    void IOService::startSocket(ChannelBase * socket)
    {

        // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
        socket->mRecvStrand.post([this, socket]()
        {


#ifdef CHANNEL_LOGGING
            socket->mLog.push("initRecv , start = " + ToString(socket->mRecvQueue.size()));
#endif

            // check to see if we should kick off a new set of recv operations. Since we are just now
            // starting the channel, its possible that the async connect call returned and the caller scheduled a receive
            // operation. But since the channel handshake just finished, those operations didn't start. So if
            // the queue has anything in it, we should actually start the operation now...

            if (socket->mRecvQueue.size())
            {
                // ok, so there isn't any recv operations currently underway. Lets kick off the first one. Subsequent recvs
                // will be kicked off at the completion of this operation.
                receiveOne(socket);
            }


            socket->mRecvSocketSet = true;

            auto ii = ++socket->mOpenCount;
            if (ii == 2)
                socket->mOpenProm.set_value();
        });


        // a strand is like a lock. Stuff posted (or dispatched) to a strand will be executed sequentially
        socket->mSendStrand.post([this, socket]()
        {
            // the queue must be guarded from concurrent access, so add the op within the strand

            auto start = socket->mSendQueue.size();
#ifdef CHANNEL_LOGGING
            socket->mLog.push("initSend , start = " + ToString(start));
#endif
            // check to see if we should kick off a new set of send operations. Since we are just now
            // starting the channel, its possible that the async connect call returned and the caller scheduled a send
            // operation. But since the channel handshake just finished, those operations didn't start. So if
            // the queue has anything in it, we should actually start the operation now...

            if (start)
            {
                // ok, so there isn't any send operations currently underway. Lets kick off the first one. Subsequent sends
                // will be kicked off at the completion of this operation.
                sendOne(socket);
            }

            socket->mSendSocketSet = true;

            auto ii = ++socket->mOpenCount;
            if (ii == 2)
                socket->mOpenProm.set_value();

        });
    }

}
