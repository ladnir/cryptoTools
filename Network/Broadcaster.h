#pragma once
#include "Network/Endpoint.h"
#include "Network/Channel.h"
#include "Common/Defines.h"
#include <vector>

namespace osuCrypto
{


    class Broadcaster //: public Channel
    {
    public:
        Broadcaster();
        Broadcaster(std::vector<Endpoint*> endpoints, std::string name, u64 idx);
        ~Broadcaster();

        void connect(std::vector<Endpoint*> endpoints, std::string name, u64 idx);


        /// <summary>The handle for this channel. Both ends will always have the same name.</summary>
        std::string getName() const;

        /// <summary>Data will be sent over the network asynchronously. WARNING: data lifetime must be handled by caller.</summary>
        void asyncSend(const void * bufferPtr, u64 length);

        /// <summary>Buffer will be MOVED and then sent over the network asynchronously. </summary>
        void asyncSend(std::unique_ptr<ChannelBuffer> mH);

        /// <summary>Synchronous call to send data over the network. </summary>
        void send(const void * bufferPtr, u64 length);

    private:

        std::vector<Channel*> mChls;
        std::string mName;
    };

}
