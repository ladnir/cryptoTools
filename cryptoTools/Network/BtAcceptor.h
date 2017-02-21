#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/BtSocket.h>
#include <list>
#include <future>
#include <unordered_map>
#include <atomic>
#include <cryptoTools/Network/BtSocket.h>

namespace osuCrypto {

    class BtSocket;
    class Channel;
    class BtIOService;
    struct BtIOOperation;

    class BtAcceptor
    {

    public:
        BtAcceptor() = delete;
        BtAcceptor(const BtAcceptor&) = delete;

        BtAcceptor(BtIOService& ioService);
        ~BtAcceptor();

        std::promise<void> mStoppedListeningPromise, mSocketChannelPairsRemovedProm;
        std::future<void> mStoppedListeningFuture, mSocketChannelPairsRemovedFuture;

        BtIOService& mIOService;

        boost::asio::ip::tcp::acceptor mHandle;

        std::atomic<bool> mStopped;
        std::mutex mSocketChannelPairsMtx;
        std::unordered_map<std::string, std::pair<boost::asio::ip::tcp::socket*, Channel*>> mSocketChannelPairs;

        void asyncSetSocket(
            std::string endpointName,
            std::string localChannelName,
            std::string remoteChannelName,
            boost::asio::ip::tcp::socket* handel);

        void asyncGetSocket(Channel& chl);

        void remove(std::string endpoint, std::string localName, std::string remoteName);

        u64 mPort;
        boost::asio::ip::tcp::endpoint mAddress;

        void bind(u32 port, std::string ip);
        void start();
        void stop();
        bool stopped() const;
    };

}
