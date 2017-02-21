#include <cryptoTools/Network/BtEndpoint.h>
#include <cryptoTools/Network/BtIOService.h>
#include <cryptoTools/Network/BtChannel.h>
#include <cryptoTools/Network/BtAcceptor.h>
#include <cryptoTools/Common/ByteStream.h>
#include <cryptoTools/Network/BtSocket.h>
#include <cryptoTools/Common/Log.h>


#include <sstream>

namespace osuCrypto {

    //extern std::vector<std::string> split(const std::string &s, char delim);


    void BtEndpoint::start(BtIOService& ioService, std::string remoteIP, u32 port, EpMode type, std::string name)
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

    void BtEndpoint::start(BtIOService& ioService, std::string address, EpMode host, std::string name)
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

    BtEndpoint::~BtEndpoint()
    {
    }

    std::string BtEndpoint::getName() const
    {
        return mName;
    }


    Channel & BtEndpoint::addChannel(std::string localName, std::string remoteName)
    {
        if (remoteName == "") remoteName = localName;
        Channel* chlPtr;

        // first, add the channel to the endpoint.
        {
            std::lock_guard<std::mutex> lock(mAddChannelMtx);

            if (mStopped == true)
            {
                throw std::runtime_error("rt error at " LOCATION);
            }

            mChannels.emplace_back(*this, localName, remoteName);
            chlPtr = &mChannels.back();
        }

        Channel& chl = *chlPtr;


        if (mMode == EpMode::Server)
        {
            // the acceptor will do the handshake, set chl.mHandel and
            // kick off any send and receives which may happen after this
            // call but before the handshake completes
            mAcceptor->asyncGetSocket(chl);
            chl.mId = 0;

        }
        else
        {
            chl.mHandle.reset(new boost::asio::ip::tcp::socket(getIOService().mIoService));
            //std::cout << IoStream::lock << "new socket: " << chl.mHandle.get() << std::endl << IoStream::unlock;

             
            chl.mId = 1;

            boost::system::error_code ec;

            //std::cout << "Endpoint connect " << mName << " " << localName << " " << remoteName << std::endl;

            auto initialCallback = new std::function<void(const boost::system::error_code&)>();
            auto timer = new boost::asio::deadline_timer(getIOService().mIoService, boost::posix_time::milliseconds(10));

            *initialCallback = [&, timer, initialCallback, localName, remoteName](const boost::system::error_code& ec)
            {
                //std::cout << "Endpoint connect call back " << std::endl;

                if (ec && chl.mStopped == false && this->stopped() == false)
                {
                    //std::cout << IoStream::lock << "        failed, retrying " << chl.mHandle.get() << std::endl << IoStream::unlock;

                    //auto t = new boost::asio::deadline_timer (getIOService().mIoService, boost::posix_time::milliseconds(10));


                    // tell the io service to wait 10 ms and then try again...
                    timer->async_wait([&,timer, initialCallback](const boost::system::error_code& ec)
                    {
                        if (chl.mStopped == false)
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
                                std::cout << "stopped: " << chl.mStopped << " " << stopped() << std::endl;

                                delete initialCallback;
                                delete timer;

                            }
                            else
                            {

                                //std::cout << "        failed, retrying'" << std::endl;

                                ////boost::asio::async_connect()

                                //std::cout << IoStream::lock << "connect cb handle: " << chl.mHandle.get() << std::endl << IoStream::unlock;
                                //std::cout << IoStream::lock << "initialCallback! = " << initialCallback << std::endl << IoStream::unlock;

                                chl.mHandle->async_connect(mRemoteAddr, *initialCallback);
                            }
                        }
                    });
                }
                else if (!ec)
                {
                    //std::cout << "        connected" << std::endl;

                    boost::asio::ip::tcp::no_delay option(true);
                    chl.mHandle->set_option(option);


                    std::stringstream ss;
                    ss << mName << char('`') << localName << char('`') << remoteName;

                    auto str = ss.str();

                    ByteStream buff((u8*)str.data(), str.size());

                    BtIOOperation op;
                    op.mSize = (u32)buff.size();
                    op.mType = BtIOOperation::Type::SendData;
                    op.mBuffs[1] = boost::asio::buffer((char*)buff.data(), (u32)buff.size());
                    op.mContainer = (new MoveChannelBuff<ByteStream>(std::move(buff)));

                    chl.mSendStrand.post([this, &chl, op]()
                    {
                        chl.mSendQueue.push_front(op);
                        chl.mSendSocketSet = true;

                        auto ii = ++chl.mOpenCount;
                        if (ii == 2) chl.mOpenProm.set_value();

                        getIOService().sendOne(&chl);
                    });


                    chl.mRecvStrand.post([this, &chl]()
                    {
                        chl.mRecvSocketSet = true;

                        auto ii = ++chl.mOpenCount;
                        if (ii == 2) chl.mOpenProm.set_value();

                        if (chl.mRecvQueue.size())
                        {
                            getIOService().receiveOne(&chl);
                        }
                    });

                    delete initialCallback;
                    delete timer;
                }
                else
                {
                    std::stringstream ss;
                    ss << "network error (init cb) \n  Location: " LOCATION "\n  message: "
                        << ec.message() << "\n  value: " << ec.value() << std::endl;

                    delete initialCallback;
                    delete timer;

                    std::cout << ss.str() << std::flush;
                    throw std::runtime_error(LOCATION);
                }
            };


            //std::cout << IoStream::lock << "initialCallback = " << initialCallback << std::endl << IoStream::unlock;
            chl.mHandle->async_connect(mRemoteAddr, *initialCallback);
        }

        return chl;
    }


    void BtEndpoint::stop()
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

    bool BtEndpoint::stopped() const
    {
        return mStopped;
    }

    void BtEndpoint::removeChannel(std::string  chlName)
    {
        std::lock_guard<std::mutex> lock(mAddChannelMtx);

        auto iter = mChannels.begin();

        while (iter != mChannels.end())
        {
            auto name = iter->getName();
            if (name == chlName)
            {
                //std::cout << IoStream::lock << "removing " << getName() << " "<< name << " = " << chlName << IoStream::unlock << std::endl;
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