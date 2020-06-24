#include <cryptoTools/Common/config.h>
#ifdef ENABLE_BOOST


#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Finally.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IoBuffer.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Crypto/AES.h>

#include <stdio.h>
#include <algorithm>
#include <sstream>
#include "util.h"

namespace osuCrypto
{

    void post(IOService* ios, std::function<void()>&& fn)
    {
        ios->mIoService.post(std::move(fn));
    }



#ifdef ENABLE_NET_LOG
#define LOG_MSG(m) mLog.push(m)
#define IF_LOG(m) m
#else
#define LOG_MSG(m)
#define IF_LOG(m)
#endif

    Work::Work(IOService& ios, std::string reason)
        : mWork(new boost::asio::io_service::work(ios.mIoService))
        , mReason(reason)
        , mIos(ios)
    {
#ifdef ENABLE_NET_LOG
        std::lock_guard<std::mutex> lock(mIos.mWorkerMtx);
        ios.mWorkerLog.insert({mWork.get(), reason});
#endif
    }
    Work::~Work()
    {
        reset();
    }

    void Work::reset()
    {
        if(mWork)
        {
#ifdef ENABLE_NET_LOG
            std::lock_guard<std::mutex> lock(mIos.mWorkerMtx);
            auto iter = mIos.mWorkerLog.find(mWork.get());
            mIos.mWorkerLog.erase(iter);
#endif
            mWork.reset(nullptr);
        }
    }

    Acceptor::Acceptor(IOService& ioService)
        :
        //mSocketChannelPairsRemovedFuture(mSocketChannelPairsRemovedProm.get_future()),
        mPendingSocketsEmptyFuture(mPendingSocketsEmptyProm.get_future()),
        mStoppedFuture(mStoppedPromise.get_future()),
        mIOService(ioService),
        mStrand(ioService.mIoService.get_executor()),
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
        //boost::asio::ip::tcp::resolver::query query(ip, pStr);

        auto addrIter = resolver.resolve(ip, pStr, ec);

        if (ec)
        {
            return;
        }

        mAddress = *addrIter;

        mHandle.open(mAddress.protocol());
        mHandle.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

        //#ifdef _MSC_VER
        //        typedef boost::asio::detail::socket_option::boolean<BOOST_ASIO_OS_DEF(SOL_SOCKET), SO_EXCLUSIVEADDRUSE> excluse_address; 
        //        mHandle.set_option(excluse_address(true));
        //#endif // _MSC_VER


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
        boost::asio::dispatch(mStrand, [&]() {
            if (isListening())
            {
                mPendingSockets.emplace_back(mIOService.mIoService);
                auto sockIter = mPendingSockets.end(); --sockIter;

                //#ifdef ENABLE_NET_LOG
                sockIter->mIdx = mPendingSocketIdx++;
                //#endif
                LOG_MSG("listening with socket#" + std::to_string(sockIter->mIdx) +
                    " at " + mAddress.address().to_string() + " : " + std::to_string(mAddress.port()));

                //BoostSocketInterface* newSocket = new BoostSocketInterface(mIOService.mIoService);
                mHandle.async_accept(sockIter->mSock, [sockIter, this](const boost::system::error_code& ec)
                    {
                        //std::cout << "async_accept cb socket#" + std::to_string(sockIter->mIdx) << " " << ec.message() <<  std::endl;

                        start();

                        if (!ec)
                        {

                            boost::asio::ip::tcp::no_delay option(true);
                            boost::system::error_code ec2;
                            sockIter->mSock.set_option(option, ec2);
                            if (ec2)
                                erasePendingSocket(sockIter);
                            else
                                sendServerMessage(sockIter);
                        }
                        else
                        {
                            LOG_MSG("Failed with socket#" + std::to_string(sockIter->mIdx) + " ~ " + ec.message());


                            if (ec.value() == boost::asio::error::no_descriptors)
                            {
                                mIOService.printError("Too many sockets have been opened and the OS is refusing"
                                    " to give more. Increase the maximum number of file descriptors or use fewer sockets\n");

                            }
                            
                            // if the error code is not for operation canceled, print it to the terminal.
                            if (ec.value() != boost::asio::error::operation_aborted && mIOService.mPrint)
                                std::cout << "Acceptor.listen failed for socket#" << std::to_string(sockIter->mIdx) << " at port "<< mPort 
                                    << " ~~ " << ec.message() << " " << ec.value() << std::endl;

                            erasePendingSocket(sockIter);
                        }
                    });
            }
            else
            {
                LOG_MSG("Stopped listening");
            }
            });

    }


    void Acceptor::erasePendingSocket(std::list<details::PendingSocket>::iterator sockIter)
    {
        boost::asio::dispatch(mStrand, [&, sockIter]() {

            boost::system::error_code ec3;
            sockIter->mSock.close(ec3);

            mPendingSockets.erase(sockIter);
            if (stopped() && mPendingSockets.size() == 0)
                mPendingSocketsEmptyProm.set_value();
            });
    }

    void Acceptor::sendServerMessage(std::list<details::PendingSocket>::iterator sockIter)
    {
        sockIter->mBuff.resize(1);
        sockIter->mBuff[0] = 'q';
        auto buffer = boost::asio::buffer((char*)sockIter->mBuff.data(), sockIter->mBuff.size());

        sockIter->mSock.async_send(buffer, [this, sockIter](const error_code& ec, u64 bytesTransferred) {
            if (ec || bytesTransferred != 1)
                erasePendingSocket(sockIter);
            else
                recvConnectionString(sockIter);

            }
        );
    }

    void Acceptor::recvConnectionString(std::list<details::PendingSocket>::iterator sockIter)
    {
        LOG_MSG("Connected with socket#" + std::to_string(sockIter->mIdx));


        sockIter->mBuff.resize(sizeof(u32));
        auto buffer = boost::asio::buffer((char*)sockIter->mBuff.data(), sockIter->mBuff.size());
        sockIter->mSock.async_receive(buffer,
            [sockIter, this](const boost::system::error_code& ec, u64 bytesTransferred)
            {
                if (!ec)
                {
                    LOG_MSG("Recv header with socket#" + std::to_string(sockIter->mIdx));

                    auto size = *(u32*)sockIter->mBuff.data();

                    sockIter->mBuff.resize(size);
                    auto buffer = boost::asio::buffer((char*)sockIter->mBuff.data(), sockIter->mBuff.size());

                    sockIter->mSock.async_receive(buffer,
                        bind_executor(mStrand, [sockIter, this](const boost::system::error_code& ec3, u64 bytesTransferred2) {
                            if (!ec3)
                            {
                                LOG_MSG("Recv boby with socket#" + std::to_string(sockIter->mIdx) + " ~ " + sockIter->mBuff);

                                asyncSetSocket(
                                    std::move(sockIter->mBuff),
                                    std::unique_ptr<BoostSocketInterface>(
                                        new BoostSocketInterface(std::move(sockIter->mSock))));
                            }
                            else
                            {
                                std::stringstream ss;
                                ss << "socket header body failed: " << ec3.message() << std::endl;
                                mIOService.printError(ss.str());
                                LOG_MSG("Recv body failed with socket#" + std::to_string(sockIter->mIdx) + " ~ " + ec3.message());
                            }

                            erasePendingSocket(sockIter);
                            }
                        )
                    );

                }
                else
                {
                    if (ec.value() != boost::asio::error::operation_aborted)
                    {
                        std::stringstream ss;
                        ss << "async_accept error, failed to receive first header on connection handshake."
                            << " Other party may have closed the connection. Error code:"
                            << ec.message() << "  " << LOCATION << std::endl;
                        mIOService.printError(ss.str());
                    }

                    LOG_MSG("Recv header failed with socket#" + std::to_string(sockIter->mIdx) + " ~ " + ec.message());

                    erasePendingSocket(sockIter);
                }

            }
        );
    }

    void Acceptor::stop()
    {
        if (mStopped == false)
        {
            boost::asio::dispatch(mStrand, [&]() {
                if (mStopped == false)
                {
                    mStopped = true;
                    mListening = false;

                    LOG_MSG("accepter Stopped");


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

            status = mStoppedFuture.wait_for(timeout);
            while (status == std::future_status::timeout)
            {
                status = mStoppedFuture.wait_for(timeout);
                std::cout << "waiting on acceptor to close. hasSubsciptions() = " << hasSubscriptions() << std::endl;
                IF_LOG(lout << mLog << std::endl
                    << mIOService.mLog << std::endl);
            }


            mPendingSocketsEmptyFuture.get();
            mStoppedFuture.get();

        }
    }


    bool Acceptor::hasSubscriptions() const
    {
        for (auto& a : mGroups)
            if (a->hasSubscriptions())
                return true;

        return false;
    }
    void Acceptor::stopListening()
    {

        boost::asio::dispatch(mStrand, [&]() {
            if (hasSubscriptions() == false)
            {

                mListening = false;

                //std::cout << IoStream::lock << "stop listening " << std::endl << IoStream::unlock;
                mHandle.close();

                if (stopped())
                {
                    LOG_MSG("stopping prom funfilled");
                    mStoppedPromise.set_value();
                }
                else
                {
                    LOG_MSG("stopped listening but not prom funfilled");
                }
            }
            else
            {
                LOG_MSG("stopped listening called but deferred..");
            }
            });

    }
    template<typename T>
    std::string ptrStr(const T* ptr)
    {
        std::stringstream ss;
        ss << std::hex << (u64)ptr;
        return ss.str();
    }

    void Acceptor::unsubscribe(SessionBase* session)
    {
        std::promise<void> p;
        std::future<void> f(p.get_future());
        //auto weak = session->mGroup;

        //if (session->mSessionID == 0)
        //    lout << "session 0" << std::endl;

        boost::asio::dispatch(mStrand, [&, session]() {

            IF_LOG(mLog.push("session " + session->mName + " " + std::to_string(session->mSessionID) + " " + ptrStr(session) + " unsubscribe."));

            auto group = session->mGroup;
            group->mBase.reset();

            if (group->hasSubscriptions() == false)
            {
                group->removeMapping();
                mGroups.erase(group->mSelfIter);
            }

            // if no one else wants us to listen, stop listening
            if (hasSubscriptions() == false)
                stopListening();

            p.set_value();
            });

        mIOService.workUntil(f);

        f.get();
    }

    void Acceptor::asyncSubscribe(std::shared_ptr<SessionBase>& session, completion_handle ch)
    {
        //std::promise<void> p;
        //std::future<void> f = p.get_future();

        session->mAcceptor = this;

        boost::asio::dispatch(mStrand, [&, session, ch = std::move(ch)]() {

            if (mStopped)
            {
                auto ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
                ch(ec);
            }
            else
            {
                mGroups.emplace_back(std::make_shared<details::SessionGroup>());
                auto iter = mGroups.end(); --iter;
                auto& group = *iter;
                group->mSelfIter = iter;

                std::stringstream s;
                s << std::hex << (u64) & *session;
                LOG_MSG("subscribe(" + s.str() + ")");

                group->mBase = session;
                session->mGroup = group;

                auto key = session->mName;
                auto& collection = mUnclaimedGroups[key];
                collection.emplace_back(iter);
                auto deleteIter = collection.end(); --deleteIter;

                group->removeMapping = [&, deleteIter, key]()
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
                        ch(ec);
                        return;
                    }

                    start();
                }

                auto ec = boost::system::errc::make_error_code(boost::system::errc::success);
                ch(ec);

            }
        });

        // may throw
        //f.get();
    }

    //void Acceptor::subscribe(std::shared_ptr<ChannelBase>& chl)
    //{
    //    boost::asio::dispatch(mStrand, [chl]() {
    //        chl->mSession->mGroup->mPendingChls++;
    //        });
    //}

    Acceptor::SocketGroupList::iterator Acceptor::getSocketGroup(const std::string& sessionName, u64 sessionID)
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
        auto groupIter = mUnclaimedSockets.insert({ sessionName, {} }).first;
        auto& group = groupIter->second;

        group.emplace_back(socketIter);
        auto deleteIter = group.end(); --deleteIter;

        socketIter->removeMapping = [&group, this, sessionName, deleteIter]() {
            group.erase(deleteIter);
            if (group.size() == 0) mUnclaimedSockets.erase(mUnclaimedSockets.find(sessionName));
        };

        return socketIter;

    }

    void Acceptor::cancelPendingChannel(std::shared_ptr<ChannelBase> chl)
    {
        //std::promise<void> prom;

        boost::asio::dispatch(mStrand, [this, chl]() {


            auto group = chl->mSession->mGroup;
            auto chlIter = std::find_if(group->mChannels.begin(), group->mChannels.end(),
                [&](const std::shared_ptr<ChannelBase>& c) { return c == chl; });

            if (chlIter != group->mChannels.end())
            {
                LOG_MSG("cancelPendingChannel(...) Channel "
                    + chl->mSession->mName + " "
                    + std::to_string(chl->mSession->mSessionID) + " "
                    + chl->mLocalName + " " + chl->mRemoteName);

                group->mChannels.erase(chlIter);

                if (group->hasSubscriptions() == false)
                {
                    group->removeMapping();
                    mGroups.erase(group->mSelfIter);

                    if (hasSubscriptions() == false)
                        stopListening();
                }
            }


            auto ec = boost::system::errc::make_error_code(boost::system::errc::operation_canceled);
            chl->mStartOp->setSocket(nullptr, ec);


            }
        );

        //prom.get_future().get();
    }


    bool Acceptor::stopped() const
    {
        return mStopped;
    }
    std::string Acceptor::print() const
    {
        return std::string();
    }

    void Acceptor::asyncGetSocket(std::shared_ptr<ChannelBase> chl)
    {
        if (stopped()) throw std::runtime_error(LOCATION);
        LOG_MSG("queuing getSocket(...) Channel "
            + chl->mSession->mName + " "
            + chl->mLocalName + " "
            + chl->mRemoteName + " matched = " + std::to_string(chl->mHandle == nullptr));

        boost::asio::dispatch(mStrand, [&, chl]() {

            auto& sessionGroup = chl->mSession->mGroup;
            auto& sessionName = chl->mSession->mName;
            auto& sessionID = chl->mSession->mSessionID;

            // add this channel to the list of channels in this session
            // that are looking for a matching socket. If a existing socket 
            // is a match, they are paired up. Otherwise the acceptor 
            // will pair them up once the matching socket is connected                
            sessionGroup->add(chl, this);

            // check if this session has already been paired up with
            // sockets. When this happens the client gives the session
            // a unqiue ID.
            if (sessionID)
            {
                LOG_MSG("getSocket(...) Channel " + sessionName + " " + chl->mLocalName + " " + chl->mRemoteName + " matched = " + std::to_string(chl->mHandle == nullptr));

                // remove this session group if it is no longer active.
                if (sessionGroup->hasSubscriptions() == false)
                {
                    sessionGroup->removeMapping();
                    mGroups.erase(sessionGroup->mSelfIter);

                    if (hasSubscriptions() == false)
                        stopListening();
                }
            }
            else
            {

                auto socketGroup = mSockets.end();

                // check to see if there is a socket group with the same session name
                // and has a socket with the same name as this channel.
                auto unclaimedSocketIter = mUnclaimedSockets.find(sessionName);
                if (unclaimedSocketIter != mUnclaimedSockets.end())
                {
                    auto& groups = unclaimedSocketIter->second;
                    auto matchIter = std::find_if(groups.begin(), groups.end(),
                        [&](const SocketGroupList::iterator& g) { return g->hasMatchingSocket(chl); });

                    if (matchIter != groups.end())
                        socketGroup = *matchIter;
                }

                // check if we have matching sockets.
                if (socketGroup != mSockets.end())
                {
                    // merge the group of sockets into the SessionGroup.
                    sessionGroup->merge(*socketGroup, this);


                    LOG_MSG("Session group " + sessionName + " " + std::to_string(sessionID)
                        + " matched up with a socket group on channel " + chl->mLocalName + " " + chl->mRemoteName);

                    // erase the mapping for these sockets being unclaimed.
                    socketGroup->removeMapping();
                    sessionGroup->removeMapping();

                    // erase the sockets.
                    mSockets.erase(socketGroup);

                    // check if we can erase this session group (session closed).
                    if (sessionGroup->hasSubscriptions() == false)
                    {
                        mGroups.erase(sessionGroup->mSelfIter);
                        if (hasSubscriptions() == false)
                            stopListening();
                    }
                    else
                    {
                        // If not then add this SessionGroup to the list of claimed
                        // sessions. Remove the unclaimed channel mapping
                        auto fullKey = sessionName + std::to_string(sessionID);

                        auto pair = mClaimedGroups.insert({ fullKey, sessionGroup->mSelfIter });
                        auto s = pair.second;
                        auto location = pair.first;
                        if (s == false)
                            throw std::runtime_error(LOCATION);

                        sessionGroup->removeMapping = [&, location]() {
                            mClaimedGroups.erase(location); };
                    }
                }
            }
            });
    }



    void Acceptor::asyncSetSocket(
        std::string name,
        std::unique_ptr<BoostSocketInterface> s)
    {
        auto ss = s.release();
        boost::asio::dispatch(mStrand, [this, name, ss]() {
            std::unique_ptr<BoostSocketInterface> sock(ss);

            auto names = split(name, '`');

            if (names.size() != 4)
            {
                std::cout << "bad channel name: " << name << "\nDropping the connection" << std::endl;
                LOG_MSG("socket " + name + " has a bad name. Connection dropped");
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

            // first check if we have already paired this sessionName || sessionID
            // up with a local session. If so then we can give this new socket
            // to that session group and it will figure out what Channel should get the socket.
            auto fullKey = sessionName + std::to_string(sessionID);
            auto claimedIter = mClaimedGroups.find(fullKey);
            if (claimedIter != mClaimedGroups.end())
            {
                LOG_MSG("socket " + name + " matched with existing session: " + fullKey);

                // add this socket to the group. It will be matched with a Channel
                // if there is one waiting for the socket or the socket be stored 
                // in the group to wait for a matching Channel.
                auto& group = *claimedIter->second;
                group->add(std::move(socket), this);

                // check to is if this group is empty. If so the Session has been destroyed
                // and all Channels have gotten a socket. We can therefore safely remove
                // this group.
                if (group->hasSubscriptions() == false)
                {
                    LOG_MSG("SessionGroup " + fullKey + " is empty. Removing it.");
                    group->removeMapping();
                    mGroups.erase(group->mSelfIter);

                    // check if the Acceptor in general has no more objects
                    // wanting sockets. If so, then stop listening for sockets
                    if (hasSubscriptions() == false)
                        stopListening();
                }
                return;
            }

            // This means we do not have an existing session group to put this
            // socket in. Lets first put this socket into a socket group which
            // has the same session ID as the new socket. If no such socket group
            // exists then this will make one.
            auto socketGroup = getSocketGroup(sessionName, sessionID);

            GroupList::iterator sessionGroupIter = mGroups.end();

            // In the event that this is the first socket with this session Name/ID,
            // see if there is a matching unclaimed session group that has a matching 
            // name and has a channel with the same name as this socket. If so, set
            // the sessionGroup pointer to point at it.
            auto unclaimedLocalIter = mUnclaimedGroups.find(sessionName);
            if (unclaimedLocalIter != mUnclaimedGroups.end())
            {
                auto& groups = unclaimedLocalIter->second;
                auto matchIter = std::find_if(groups.begin(), groups.end(),
                    [&](const GroupList::iterator& g) {
                        return (*g)->hasMatchingChannel(socket); });

                if (matchIter != groups.end())
                {
                    sessionGroupIter = *matchIter;
                    //groups.erase(matchIter);
                    //if (groups.size() == 0)
                    //{
                    //    mUnclaimedGroups.erase(unclaimedLocalIter);
                    //}
                }
            }

            // add the socket to the SocketGroup.
            socketGroup->mSockets.emplace_back(std::move(socket));

            // Check if we found a matching session group. If so, we can merge
            // the socket group with the session group
            if (sessionGroupIter != mGroups.end())
            {
                auto& sessionGroup = *sessionGroupIter;

                std::stringstream s;
                s << std::hex << (u64) & *sessionGroup->mBase.lock();

                LOG_MSG("Socket group " + fullKey + " matched up with a session group on channel "
                    + localName + " " + remoteName + " of "
                    + std::to_string(unclaimedLocalIter->second.size()) + " ~~ " + s.str());

                // merge the sockets into the group of cahnnels.
                sessionGroup->merge(*socketGroup, this);

                // mark these sockets as claimed and remove them from the list of 
                // unclaimed groups. The session group will be added as a claimed group.
                socketGroup->removeMapping();
                sessionGroup->removeMapping();

                // remove the actual socket group since it has been merged 
                // into the session group.
                mSockets.erase(socketGroup);

                // check if we can erase this session group (session closed and all channels have socket).
                if (sessionGroup->hasSubscriptions() == false)
                {
                    LOG_MSG("Session Group " + fullKey + " is empty via merge. Removing it.");
                    mGroups.erase(sessionGroupIter);

                    // check if the accept in general has no more objects
                    // wanting sockets. If so, stop listening.
                    if (hasSubscriptions() == false)
                    {
                        LOG_MSG("Session Group " + fullKey + " stopping listening... ");
                        stopListening();
                    }
                    else
                    {
                        LOG_MSG("Session Group " + fullKey + " NOT stopping listening... ");

                    }
                }
                else
                {
                    // If not then add this SessionGroup to the list of claimed
                    // sessions. Remove the unclaimed channel mapping
                    auto pair = mClaimedGroups.insert({ fullKey, sessionGroupIter });
                    auto s = pair.second;
                    auto location = pair.first;
                    if (s == false)
                        throw std::runtime_error(LOCATION);

                    // update how to remove this session group from the list of claimed groups.
                    // Will be called when its time to remove this session.
                    sessionGroup->removeMapping = [&, location]() { mClaimedGroups.erase(location); };
                }
            }
            });

    }


    //extern void split(const std::string &s, char delim, std::vector<std::string> &elems);
    //extern std::vector<std::string> split(const std::string &s, char delim);

    block IOService::getRandom()
    {
        return AES(mRandSeed).ecbEncBlock(toBlock(mSeedIndex++));
    }

    IOService::IOService(u64 numThreads)
        :
        mRandSeed(sysRandomSeed()),
        mSeedIndex(0),
        mIoService(),
        mStrand(mIoService.get_executor()),
        mWorker(*this, "ios")
    {
        // if they provided 0, the use the number of processors worker threads
        numThreads = (numThreads) ? numThreads : std::thread::hardware_concurrency();
        mWorkerThrds.resize(numThreads);
        u64 i = 0;
        // Create worker threads based on the number of processors available on the
        // system. Create two worker threads for each processor
        for (auto& thrdProm : mWorkerThrds)
        {
            auto& thrd = thrdProm.first;
            auto& prom = thrdProm.second;

            // Create a server worker thread and pass the completion port to the thread
            thrd = std::thread([this, i, &prom]()
                {
                    setThreadName("io_Thrd_" + std::to_string(i));
                    mIoService.run();
                    prom.set_value();
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


    void IOService::workUntil(std::future<void>& f)
    {
        while (f.wait_for(std::chrono::microseconds(0)) != std::future_status::ready)
            mIoService.poll_one();
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

            mWorker.reset();

            // we can now join on them.
            for (auto& thrd : mWorkerThrds)
            {
                auto res = thrd.second.get_future().wait_for(std::chrono::seconds(3));
                if(res != std::future_status::ready && mPrint)
                {
#ifdef ENABLE_NET_LOG
                    std::lock_guard<std::mutex> lock(mWorkerMtx);
                    if(mWorkerLog.size())
                    {
                        lout << "IOSerive::stop() is waiting for: \n"; 
                        for(auto& v : mWorkerLog)
                            lout << '\t' << v.second << "\n";
                        lout << std::flush;
                    }
#else
                    lout << "IOSerive::stop() is waiting for work to finish" << std::endl;
#endif
                }

                thrd.first.join();
            }
            // clean their state.
            mWorkerThrds.clear();
        }
    }

    void IOService::printError(std::string msg)
    {
        if (mPrint)
            std::cerr << msg << std::endl;
    }

    void IOService::showErrorMessages(bool v)
    {
        mPrint = v;
    }


    void IOService::aquireAcceptor(std::shared_ptr<SessionBase>& session)
    {
        //std::atomic<bool> flag(false);
        std::list<Acceptor>::iterator acceptorIter;
        std::promise<void> p;
        //std::future<std::list<Acceptor>::iterator> f = p.get_future();
        //boost::asio::post
        boost::asio::dispatch(mStrand, [&]()
            {
                // see if there already exists an acceptor that this endpoint can use.
                acceptorIter = std::find_if(
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
                }

                acceptorIter->asyncSubscribe(session, [&](const error_code& ec) {
                    if (ec)
                        p.set_exception(std::make_exception_ptr(std::runtime_error(ec.message())));
                    else
                        p.set_value();
                    });
            });


        TODO("do something else that does not require workUntil.");
        auto f = p.get_future();
        // contribute this thread to running the dispatch. Sometimes needed.
        workUntil(f);

        f.get();
    }



    osuCrypto::details::SessionGroup::~SessionGroup()
    {
        if (hasSubscriptions())
            lout << "logic error " LOCATION << std::endl;

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
#ifdef ENABLE_NET_LOG
            a->mLog.push("handing the socket to Channel : " + s.mLocalName + "`" + s.mRemoteName);
#endif
            auto ec = boost::system::errc::make_error_code(boost::system::errc::success);
            (*iter)->mStartOp->setSocket(std::move(s.mSocket), ec);
            mChannels.erase(iter);
        }
        else
        {
#ifdef ENABLE_NET_LOG
            a->mLog.push("storing in group the socket -> " + s.mLocalName + "`" + s.mRemoteName);
#endif
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
            auto ec = boost::system::errc::make_error_code(boost::system::errc::success);
            chl->mStartOp->setSocket(std::move(iter->mSocket), ec);
            mSockets.erase(iter);
        }
        else
        {
            mChannels.emplace_back(chl);
        }
    }

    bool details::SessionGroup::hasMatchingChannel(const NamedSocket& s) const
    {
        return mChannels.end() != std::find_if(mChannels.begin(), mChannels.end(),
            [&](const std::shared_ptr<ChannelBase>& chl)
            {
                return chl->mLocalName == s.mLocalName &&
                    chl->mRemoteName == s.mRemoteName;
            });
    }

    details::SocketGroup::~SocketGroup()
    {
        //if (mSockets.size() && )
        //    lout << "logic error " LOCATION << std::endl;
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

        auto session = mBase.lock();
        if (session)
        {
            if (merge.mSessionID == 0 ||
                session->mName != merge.mName ||
                session->mSessionID)
                throw std::runtime_error(LOCATION);

            session->mSessionID = merge.mSessionID;
        }
        else if (mChannels.size())
        {
            mChannels.front()->mSession->mSessionID = merge.mSessionID;

        }


        for (auto& s : merge.mSockets) add(std::move(s), a);
        merge.mSockets.clear();
    }




}
#endif