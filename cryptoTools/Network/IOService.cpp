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
                std::cout << "waiting on acceptor to close " << mPendingSockets.size() << " pending socket" << std::endl;
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
        auto ss = s.release();
        mStrand.dispatch([this, name, ss]() {
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

    void IOService::printError(std::string msg)
    {
        if(mPrint)
            std::cerr << msg << std::endl;
    }

    void IOService::showErrorMessages(bool v)
    {
        mPrint = v;
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
            (*iter)->startSocket(std::move(s.mSocket));
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
            chl->startSocket(std::move(iter->mSocket));
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
