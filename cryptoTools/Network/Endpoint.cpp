#include <cryptoTools/Network/Endpoint.h>
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


    void Endpoint::start(IOService& ioService, std::string remoteIP, u32 port, EpMode type, std::string name)
    {
        if (mBase && mBase->mStopped == false)
            throw std::runtime_error("rt error at " LOCATION);

		mBase.reset(new EndpointBase);
        mBase->mIP = (remoteIP);
        mBase->mPort = (port);
        mBase->mMode = (type);
        mBase->mIOService = &(ioService);
        mBase->mStopped = (false);
        mBase->mName = (name);

        if (type == EpMode::Server)
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
        //ioService.mEndpointStopFutures.push_back(mBase->mDoneFuture);

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

	// See start(...)

	Endpoint::Endpoint(IOService & ioService, std::string address, EpMode type, std::string name)
	{
		start(ioService, address, type, name);
	}

	// See start(...)

	Endpoint::Endpoint(IOService & ioService, std::string remoteIP, u32 port, EpMode type, std::string name)
	{
		start(ioService, remoteIP, port, type, name);
	}


	// Default constructor

	Endpoint::Endpoint()
	{ }

	Endpoint::Endpoint(std::shared_ptr<EndpointBase>& c)
		: mBase(c)
	{ }

	Endpoint::~Endpoint()
    {
        //stop();
    }

    std::string Endpoint::getName() const
    {
		if (mBase)
			return mBase->mName;
		else
			throw std::runtime_error(LOCATION);
    }

	IOService & Endpoint::getIOService() { 
		if(mBase)
			return *mBase->mIOService;
		else
			throw std::runtime_error(LOCATION);
	}


    Channel Endpoint::addChannel(std::string localName, std::string remoteName)
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
		auto chlBase = chl.mBase.get();
		auto epBase = mBase;

        if (mBase->mMode == EpMode::Server)
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
                        if (chlBase->stopped() == false)
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
                                std::cout << "stopped: " << chlBase->stopped() << " " << epBase->mStopped << std::endl;

                                delete initialCallback;
                                delete timer;

                            }
                            else
                            {
								((BoostSocketInterface*)chlBase->mHandle.get())->mSock.async_connect(epBase->mRemoteAddr, *initialCallback);
                            }
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
					if(firstAnonymousChl) ss << "`#";

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
                        base->mLog.push("initSend' #"+ToString(idx)+" , opened = " + ToString(ii == 2) + ", start = " + ToString(true));
#endif
						epBase->mIOService->sendOne(chlBase);
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
							epBase->mIOService->receiveOne(chlBase);
                        }
                    });

                    delete initialCallback;
                    delete timer;
                }
                else
                {
                    std::stringstream ss;
                    ss << "network error (init cb) " << (chlBase) << "\n  Location: " LOCATION "\n  message: "
                        << ec.message() << "\n  value: " << ec.value() << std::endl;

                    std::cout << ss.str() << std::flush;

                    if (chlBase->stopped() == false) {
						((BoostSocketInterface*)chlBase->mHandle.get())->mSock.async_connect(epBase->mRemoteAddr, *initialCallback);
                    }
                    else
                    {
                        std::cout << "stopping " << chlBase  << "   " << chlBase->mSendStatus << std::endl;
                        delete initialCallback;
                        delete timer;
                    }
                }
            };

			((BoostSocketInterface*)chlBase->mHandle.get())->mSock.async_connect(epBase->mRemoteAddr, *initialCallback);
        }

        return (chl);
    }


    void Endpoint::stop()
    {
        if (stopped() == false)
        {
			mBase->mStopped = true;
			//if (isHost())
			//{
			//	mBase->mAcceptor->removeEndpoint(this->mBase.get());
			//}
        }
    }

    bool Endpoint::stopped() const
    {
        return mBase->mStopped;
    }
    //void EndpointBase::removeChannel(ChannelBase* base)
    //{
    //    {
    //        std::lock_guard<std::mutex> lock(mAddChannelMtx);

    //        auto iter = mChannels.begin();

    //        while (iter != mChannels.end())
    //        {
    //            auto baseIter = *iter;
    //            if (baseIter == base)
    //            {
    //                //std::cout << IoStream::lock << "removing " << getName() << " "<< name << " = " << chlName << IoStream::unlock << std::endl;
    //  //              if (mAcceptor)
				//		//mAcceptor->remove(mName, base->mLocalName, base->mRemoteName);

				//	mChannels.erase(iter);
    //                break;
    //            }
    //            ++iter;
    //        }

    //        // if there are no more channels and the send point has stopped, signal that the last one was just removed.
    //        if (mStopped && mChannels.size() == 0)
    //        {
				//mDoneProm.set_value();
    //        }
    //    }
    //}
	u32 Endpoint::port() const
	{
		return mBase->mPort;
	}
	std::string Endpoint::IP() const
	{
		return mBase->mIP;
	}
	bool Endpoint::isHost() const { return mBase->mMode == EpMode::Server; }
	
	//EndpointBase::EndpointBase()
	//	:mDoneFuture(mDoneProm.get_future())
	//{ 
	//}
}