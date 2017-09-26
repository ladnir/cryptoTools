#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Acceptor.h>
#include <cryptoTools/Network/SocketAdapter.h>
#include <cryptoTools/Common/ByteStream.h>
#include <cryptoTools/Network/IoBuffer.h>
#include <cryptoTools/Common/Log.h>


#include <sstream>

namespace osuCrypto {

    //extern std::vector<std::string> split(const std::string &s, char delim);


    void Endpoint::start(IOService& ioService, std::string remoteIP, u32 port, EpMode type, std::string name)
    {
        if (mStopped == false)
            throw std::runtime_error("rt error at " LOCATION);

        mIP = (remoteIP);
        mPort = (port);
        mMode = (type);
        mIOService = &(ioService);
        mStopped = (false);
        mName = (name);

        if (type == EpMode::Server)
        {
            mAcceptor = (ioService.getAcceptor(*this));
        }
        else
        {
            boost::asio::ip::tcp::resolver resolver(mIOService->mIoService);
            boost::asio::ip::tcp::resolver::query query(remoteIP, boost::lexical_cast<std::string>(port));
            mRemoteAddr = *resolver.resolve(query);
        }

        std::lock_guard<std::mutex> lock(ioService.mMtx);
        ioService.mEndpointStopFutures.push_back(mDoneFuture);

    }

    void Endpoint::start(IOService& ioService, std::string address, EpMode host, std::string name)
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

    Endpoint::~Endpoint()
    {
        stop();
    }

    std::string Endpoint::getName() const
    {
        return mName;
    }


    Channel Endpoint::addChannel(std::string localName, std::string remoteName)
    {
        if (remoteName == "") remoteName = localName;

        Channel chl(*this, localName, remoteName);

        auto base = chl.mBase.get();


        // first, add the channel to the endpoint.
        {
            std::lock_guard<std::mutex> lock(mAddChannelMtx);

            if (mStopped == true)
            {
                throw std::runtime_error("rt error at " LOCATION);
            }

            auto iter = mChannels.begin();
            while (iter != mChannels.end())
            {
                if ((*iter)->mLocalName == localName)
                    throw std::runtime_error("Error: channel name already exists.\n   " LOCATION);

                ++iter;
            }

            mChannels.emplace_back(base);
        }


        if (mMode == EpMode::Server)
        {
            // the acceptor will do the handshake, set chl.mHandel and
            // kick off any send and receives which may happen after this
            // call but before the handshake completes
            mAcceptor->asyncGetSocket(*base);
            base->mId = 0;

        }
        else
        {
            auto sock = new BoostSocketInterface(getIOService().mIoService);
            base->mHandle.reset(sock);

            //std::cout << IoStream::lock << "new socket: " << chl.mHandle.get() << std::endl << IoStream::unlock;


            base->mId = 1;

            boost::system::error_code ec;

            //std::cout << IoStream::lock << "Endpoint connect " << mName << " " << localName << " " << remoteName << std::endl << IoStream::unlock;

            auto initialCallback = new std::function<void(const boost::system::error_code&)>();
            auto timer = new boost::asio::deadline_timer(getIOService().mIoService, boost::posix_time::milliseconds(10));

            *initialCallback = 
                [&, base, timer, initialCallback, localName, remoteName, sock]
                (const boost::system::error_code& ec)
            {
                //std::cout << IoStream::lock << "Endpoint connect call back " << std::endl << IoStream::unlock;

                if (ec && base->stopped() == false && this->stopped() == false)
                {
                    //std::cout << IoStream::lock << "        failed, retrying " << localName << std::endl << IoStream::unlock;

                    //auto t = new boost::asio::deadline_timer (getIOService().mIoService, boost::posix_time::milliseconds(10));


                    // tell the io service to wait 10 ms and then try again...
                    timer->async_wait([&, base, timer, initialCallback, sock](const boost::system::error_code& ec)
                    {
                        if (base->stopped() == false)
                        {
                            if (ec)
                            {
                                auto message = ec.message();
                                auto val = ec.value();

                                std::stringstream ss;

                                ss << "network error (wait) " << std::this_thread::get_id() << " \n  Location: " LOCATION "\n  message: ";

                                ss << message << "\n  value: ";

                                ss << val << std::endl;

                                std::cout << ss.str() << std::flush;
                                std::cout << "stopped: " << base->stopped() << " " << stopped() << std::endl;

                                delete initialCallback;
                                delete timer;

                            }
                            else
                            {

                                //std::cout << IoStream::lock << "        failed, retrying' " << localName << std::endl << IoStream::unlock;

                                ////boost::asio::async_connect()

                                //std::cout << IoStream::lock << "connect cb handle: " << chl.mHandle.get() << std::endl << IoStream::unlock;
                                //std::cout << IoStream::lock << "initialCallback! = " << initialCallback << std::endl << IoStream::unlock;

                                sock->mSock.async_connect(mRemoteAddr, *initialCallback);
                            }
                        }
                    });
                }
                else if (!ec)
                {
                    //std::cout << IoStream::lock << "        connected "<< localName  << std::endl << IoStream::unlock;

                    boost::asio::ip::tcp::no_delay option(true);
                    sock->mSock.set_option(option);


                    std::stringstream ss;
                    ss << mName << char('`') << localName << char('`') << remoteName;
                    //std::cout <<IoStream::lock << "sending " << ss.str() <<std::endl << IoStream::unlock;

                    std::string str = ss.str();




                    base->mSendStrand.post([this, base, str]() mutable
                    {
                        auto op = std::unique_ptr<IOOperation>(new MoveChannelBuff<std::string>(std::move(str)));
#ifdef CHANNEL_LOGGING
                        auto idx = op->mIdx = base->mOpIdx++;
#endif
                        base->mSendQueue.emplace_front(std::move(op));
                        base->mSendSocketSet = true;

                        auto ii = ++base->mOpenCount;
                        if (ii == 2) base->mOpenProm.set_value();
#ifdef CHANNEL_LOGGING
                        base->mLog.push("initSend' #"+ToString(idx)+" , opened = " + ToString(ii == 2) + ", start = " + ToString(true));
#endif

                        getIOService().sendOne(base);
                    });


                    base->mRecvStrand.post([this, base]()
                    {
                        base->mRecvSocketSet = true;

                        auto ii = ++base->mOpenCount;
                        if (ii == 2) base->mOpenProm.set_value();

                        auto startRecv = base->mRecvQueue.size() > 0;
#ifdef CHANNEL_LOGGING
                        base->mLog.push("initRecv' , opened = " + ToString(ii == 2) + ", start = " + ToString(startRecv));
#endif

                        if (startRecv)
                        {
                            getIOService().receiveOne(base);
                        }
                    });

                    delete initialCallback;
                    delete timer;
                }
                else
                {
                    std::stringstream ss;
                    ss << "network error (init cb) " << (base) << "\n  Location: " LOCATION "\n  message: "
                        << ec.message() << "\n  value: " << ec.value() << std::endl;

                    std::cout << ss.str() << std::flush;

                    if (base->stopped() == false)
                    {
                        sock->mSock.async_connect(mRemoteAddr, *initialCallback);
                    }
                    else
                    {
                        std::cout << "stopping " << base  << "   " << base->mSendStatus << std::endl;
                        delete initialCallback;
                        delete timer;
                        //throw std::runtime_error(LOCATION);
                    }
                }
            };


            //std::cout << IoStream::lock << "initialCallback = " << initialCallback << std::endl << IoStream::unlock;
            sock->mSock.async_connect(mRemoteAddr, *initialCallback);
        }

        return (chl);
    }


    void Endpoint::stop()
    {
        if (stopped() == false)
        {

            {
                std::lock_guard<std::mutex> lock(mAddChannelMtx);
                if (mStopped == false)
                {
                    mStopped = true;

                    if (mChannels.size() == 0)
                    {
                        mDoneProm.set_value();
                    }
                }
            }
            mDoneFuture.get();
        }
    }

    bool Endpoint::stopped() const
    {
        return mStopped;
    }
    void Endpoint::removeChannel(ChannelBase* base)
    {
        {
            std::lock_guard<std::mutex> lock(mAddChannelMtx);

            auto iter = mChannels.begin();

            while (iter != mChannels.end())
            {
                auto baseIter = *iter;
                if (baseIter == base)
                {
                    //std::cout << IoStream::lock << "removing " << getName() << " "<< name << " = " << chlName << IoStream::unlock << std::endl;
                    if (mAcceptor)
                        mAcceptor->remove(mName, base->mLocalName, base->mRemoteName);

                    mChannels.erase(iter);
                    break;
                }
                ++iter;
            }

            // if there are no more channels and the send point has stopped, signal that the last one was just removed.
            if (mStopped && mChannels.size() == 0)
            {
                mDoneProm.set_value();
            }
        }
    }
}