#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "cryptoTools/Common/Defines.h"

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Acceptor.h>
#include <cryptoTools/Network/Endpoint.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/IOService.h>
#include <list>
#include <mutex>

#include <boost/lexical_cast.hpp>

namespace osuCrypto {


    class Acceptor;
    class ChannelBase;

    enum class EpMode :  bool { Client, Server };


    class Endpoint
    {

        
        Endpoint(const Endpoint&) = delete;

        std::string mIP;
        u32 mPort;
        EpMode mMode;
        bool mStopped;
        IOService* mIOService;
        Acceptor* mAcceptor;
        std::list<ChannelBase*> mChannels;
        std::mutex mAddChannelMtx;
        std::promise<void> mDoneProm;
        std::shared_future<void> mDoneFuture;
        std::string mName;
        boost::asio::ip::tcp::endpoint mRemoteAddr;
        
        //std::unique_ptr<boost::asio::deadline_timer> mDeadlineTimer;// (getIOService().mIoService, boost::posix_time::milliseconds(10));


    public:



        void start(IOService& ioService, std::string remoteIp, u32 port, EpMode type, std::string name);
        void start(IOService& ioService, std::string address, EpMode type, std::string name);

        Endpoint(IOService & ioService, std::string address, EpMode type, std::string name)
            : mPort(0), mMode(EpMode::Client), mStopped(true), mIOService(nullptr), mAcceptor(nullptr),
            mDoneFuture(mDoneProm.get_future().share())
        {
            start(ioService, address, type, name);
        }

        Endpoint(IOService & ioService, std::string remoteIP, u32 port, EpMode type, std::string name)
            : mPort(0), mMode(EpMode::Client), mStopped(true), mIOService(nullptr), mAcceptor(nullptr),
            mDoneFuture(mDoneProm.get_future().share())
        {
            start(ioService, remoteIP, port, type, name);
        }


        Endpoint()
            : mPort(0), mMode(EpMode::Client), mStopped(true), mIOService(nullptr), mAcceptor(nullptr),
            mDoneFuture(mDoneProm.get_future().share())
        {
        }

        ~Endpoint();

        std::string getName() const;

        IOService& getIOService() { return *mIOService; }

        /// <summary>Adds a new channel (data pipe) between this endpoint and the remote. The channel is named at each end.</summary>
        Channel addChannel(std::string localName, std::string remoteName = "");


        /// <summary>Stops this Endpoint. Will block until all channels have closed.</summary>
        void stop();

        /// <summary>returns whether the endpoint has been stopped (or never isConnected).</summary>
        bool stopped() const;

        /// <summary> Removes the channel with chlName. </summary>
        void removeChannel(ChannelBase* chl);

        u32 port() const { return mPort; };

        std::string IP() const { return mIP;  }

        bool isHost() const { return mMode == EpMode::Server;
        };

    };


}
