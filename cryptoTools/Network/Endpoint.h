#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.  
#include "cryptoTools/Common/Defines.h"
#include <cryptoTools/Network/Channel.h>

#include <string>
#include <list>
#include <mutex>

namespace osuCrypto {

	class IOService;
    class Acceptor;
    class ChannelBase;

    enum class EpMode :  bool { Client, Server };


    class Endpoint
    {
    public:

		// Start an enpoint for the given IP and port in either Client or Server mode.
		// The server should use their local address on which the socket should bind.
		// The client should use the address of the server.
		// The same name should be used by both endpoints. Multiple Endpoints can be bound to the same
		// address if the same IOService is used but with different name.
        void start(IOService& ioService, std::string remoteIp, u32 port, EpMode type, std::string name);


		// Start an enpoint for the given address in either Client or Server mode.
		// The server should use their local address on which the socket should bind.
		// The client should use the address of the server.
		// The same name should be used by both endpoints. Multiple Endpoints can be bound to the same
		// address if the same IOService is used but with different name.
        void start(IOService& ioService, std::string address, EpMode type, std::string name);

		// See start(...)
        Endpoint(IOService & ioService, std::string address, EpMode type, std::string name)
			: mDoneFuture(mDoneProm.get_future().share())
        {
            start(ioService, address, type, name);
        }

		// See start(...)
        Endpoint(IOService & ioService, std::string remoteIP, u32 port, EpMode type, std::string name)
            : mDoneFuture(mDoneProm.get_future().share())
        {
            start(ioService, remoteIP, port, type, name);
        }

		// Default constructor
        Endpoint()
            : mDoneFuture(mDoneProm.get_future().share())
        { }

        ~Endpoint();

        std::string getName() const;

        IOService& getIOService() { return *mIOService; }

        // Adds a new channel (data pipe) between this endpoint and the remote. The channel is named at each end.
        Channel addChannel(std::string localName, std::string remoteName = "");


        // Stops this Endpoint. Will block until all channels have closed.
        void stop();

        // returns whether the endpoint has been stopped (or never isConnected).
        bool stopped() const;

        //  Removes the channel with chlName. 
        void removeChannel(ChannelBase* chl);

        u32 port() const { return mPort; };

        std::string IP() const { return mIP;  }

        bool isHost() const { return mMode == EpMode::Server; };


	private:
		std::string mIP;
		u32 mPort = 0;
		EpMode mMode = EpMode::Client;
		bool mStopped = true;
		IOService* mIOService = nullptr;
		Acceptor* mAcceptor = nullptr;

		std::list<ChannelBase*> mChannels;
		std::mutex mAddChannelMtx;
		std::promise<void> mDoneProm;
		std::shared_future<void> mDoneFuture;
		std::string mName;
		boost::asio::ip::tcp::endpoint mRemoteAddr;

    };


}
