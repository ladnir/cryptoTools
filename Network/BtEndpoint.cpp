#include "BtEndpoint.h"
#include "Network/BtIOService.h"
#include "Network/BtChannel.h"
#include "Network/BtAcceptor.h"
#include "Common/ByteStream.h"
#include "Network/BtSocket.h"
#include "Common/Log.h"


#include <sstream>

namespace osuCrypto {

    //extern std::vector<std::string> split(const std::string &s, char delim);
        

    void BtEndpoint::start(BtIOService& ioService, std::string remoteIP, u32 port, bool host, std::string name)
    {
        if (mStopped == false)
            throw std::runtime_error("rt error at " LOCATION);


        mIP = (remoteIP);
        mPort = (port);
        mHost = (host);
        mIOService = &(ioService);
        mStopped = (false);
        mName = (name);

        if (host)
            mAcceptor = (ioService.getAcceptor(*this));
        else
        {
            boost::asio::ip::tcp::resolver resolver(mIOService->mIoService);
            boost::asio::ip::tcp::resolver::query query(remoteIP, boost::lexical_cast<std::string>(port));
            mRemoteAddr = *resolver.resolve(query);
        }

        std::lock_guard<std::mutex> lock(ioService.mMtx);
        ioService.mEndpointStopFutures.push_back(mDoneFuture);

    }

    void BtEndpoint::start(BtIOService& ioService, std::string address, bool host, std::string name)
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

        //{
        //    std::stringstream ss;
        //    ss << mName << char('`') << localName << char('`') << remoteName;

        //    auto str = ss.str();
        //    if (str.size() > 256)
        //    {
        //        std::cout << "full channel name must be shorter than 256 characters.\n    " << str << std::endl;
        //        throw std::runtime_error(LOCATION);
        //    }
        //}


        BtChannel* chlPtr;

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

        BtChannel& chl = *chlPtr;



        if (mHost)
        {
            // the acceptor will do the handshake, set chl.mHandel and
            // kick off any send and receives which may happen after this
            // call but before the handshake completes
            mAcceptor->asyncGetHandel(chl);
            chl.mId = 0;

        }
        else
        {
            chl.mHandle = new boost::asio::ip::tcp::socket(getIOService().mIoService);

            chl.mId = 1;

            boost::system::error_code ec;


            std::function<void(const boost::system::error_code&)> initialCallback = [&, localName, remoteName](const boost::system::error_code& ec)
            {
                if (ec && chl.mStopped == false && this->stopped() == false)
                {
                    boost::asio::deadline_timer t(getIOService().mIoService, boost::posix_time::milliseconds(10));
                    
                    // tell the io service to wait 10 ms and then try again...
                    t.async_wait([&](const boost::system::error_code& ec)
                    {
                        //boost::asio::async_connect()
                        chl.mHandle->async_connect(mRemoteAddr, initialCallback);
                    });
                }
                else if ((bool)ec == false)
                {
                    boost::asio::ip::tcp::no_delay option(true);
                    chl.mHandle->set_option(option);


                    std::stringstream ss;
                    ss << mName << char('`') << localName << char('`') << remoteName;

                    auto str = ss.str();

                    ByteStream* buff(new ByteStream((u8*)str.data(), str.size()));

                    BtIOOperation op;
                    op.mSize = (u32)buff->size();
                    op.mBuffs[1] = boost::asio::buffer((char*)buff->data(), (u32)buff->size());
                    op.mType = BtIOOperation::Type::SendData;
                    op.mOther = buff;

                    chl.mSendStrand.post([this, &chl, op]()
                    {
                        chl.mSendQueue.push_front(op);
                        chl.mSendSocketSet = true;

                        auto ii = ++chl.mOpenCount;
                        if (ii == 2) chl.mOpenProm.set_value();

                        getIOService().sendOne(&chl);
                    });


                    chl.mRecvStrand.post([this, &chl, op]()
                    {
                        chl.mRecvSocketSet = true;

                        auto ii = ++chl.mOpenCount;
                        if (ii == 2) chl.mOpenProm.set_value();

                        if (chl.mRecvQueue.size())
                        {
                            getIOService().receiveOne(&chl);
                        }
                    });
                }
            };

            chl.mHandle->async_connect(mRemoteAddr, initialCallback);
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
