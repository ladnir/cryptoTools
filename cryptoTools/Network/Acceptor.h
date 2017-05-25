#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/IoBuffer.h>
#include <list>
#include <future>
#include <unordered_map>
#include <atomic>
#include <cryptoTools/Network/IoBuffer.h>

namespace osuCrypto {

    class Socket;
    class ChannelBase;
    class IOService;
    class IOOperation;
    class BoostSocketInterface;

    class Acceptor
    {

    public:
        Acceptor() = delete;
        Acceptor(const Acceptor&) = delete;

        Acceptor(IOService& ioService);
        ~Acceptor();

        std::promise<void> mStoppedListeningPromise, mSocketChannelPairsRemovedProm;
        std::future<void> mStoppedListeningFuture, mSocketChannelPairsRemovedFuture;

        IOService& mIOService;

        boost::asio::ip::tcp::acceptor mHandle;

        std::atomic<bool> mStopped;
        std::mutex mSocketChannelPairsMtx;
        std::unordered_map<std::string, std::pair<BoostSocketInterface*, ChannelBase*>> mSocketChannelPairs;

        void asyncSetSocket(
            std::string endpointName,
            std::string localChannelName,
            std::string remoteChannelName,
            BoostSocketInterface* handel);

        void asyncGetSocket(ChannelBase& chl);

        void remove(std::string endpoint, std::string localName, std::string remoteName);

        u64 mPort;
        boost::asio::ip::tcp::endpoint mAddress;

        void bind(u32 port, std::string ip);
        void start();
        void stop();
        bool stopped() const;
    };

}
