#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/BtSocket.h>
#include <list>
#include <future>
#include <unordered_map>
#include "Common/Defines.h"
#include <atomic>
#include "Network/BtSocket.h"

namespace osuCrypto {

    class BtSocket;
    class Channel;
    class BtIOService;
    struct BoostIOOperation;

    class BtAcceptor
    {

    public:
        BtAcceptor() = delete;
        BtAcceptor(const BtAcceptor&) = delete;

        BtAcceptor(BtIOService& ioService);
        ~BtAcceptor();

        std::promise<void> mStoppedPromise;
        std::future<void> mStoppedFuture;

        BtIOService& mIOService;

        boost::asio::ip::tcp::acceptor mHandle;

        std::atomic<bool> mStopped;
        std::mutex mMtx;
        std::unordered_map<std::string, std::promise<BtSocket*>> mSocketPromises;

        std::promise<BtSocket*>& getSocketPromise(
            std::string endpointName,
            std::string localChannelName,
            std::string remoteChannelName);

        BtSocket* getSocket(Channel& chl);

        u64 mPort;
        boost::asio::ip::tcp::endpoint mAddress;

        void bind(u32 port, std::string ip);
        void start();
        void stop();
        bool stopped() const;
    };

}
