#include "Broadcaster.h"

namespace osuCrypto
{



    Broadcaster::Broadcaster()
    {
    }


    Broadcaster::Broadcaster(std::vector<Endpoint*> endpoints, std::string name, u64 idx)
    {
        connect(endpoints, name, idx);
    }

    Broadcaster::~Broadcaster()
    {
    }

    void Broadcaster::connect(std::vector<Endpoint*> endpoints, std::string name, u64 idx)
    {

        if (endpoints.size() > idx)
            throw std::runtime_error(LOCATION);

        mChls.resize(endpoints.size());
        for (u64 i = 0; i < endpoints.size(); ++i)
        {
            mChls[i] = &endpoints[i]->addChannel(name);
        }

    }

    //Endpoint & Broadcaster::getEndpoint()
    //{
    //    // TODO: insert return statement here
    //    return mChls[0]->getEndpoint();
    //}

    std::string Broadcaster::getName() const
    {
        return mName;
    }

    //u64 Broadcaster::getTotalDataSent() const
    //{
    //    return mChls[0]->getTotalDataSent();
    //}

    //u64 Broadcaster::getMaxOutstandingSendData() const
    //{
    //    return mChls.back()->getMaxOutstandingSendData();
    //}

    void Broadcaster::asyncSend(const void * bufferPtr, u64 length)
    {
        for (auto chl : mChls)
        {
            chl->asyncSend(bufferPtr, length);
        }
    }

    void Broadcaster::asyncSend(std::unique_ptr<ChannelBuffer> mH)
    {
        u64 size = mH->ChannelBufferSize();
        auto data = mH->ChannelBufferData();
        auto deleter = new std::pair<std::unique_ptr<ChannelBuffer>, std::atomic<u32>>(mH.release(),(u32)mChls.size());

        std::function<void()> callback = [deleter]()
        {
            // count down the number of times this callback has been called 
            // and then delete deleter once it reaches 0, i.e. all channels
            // have sent the data.
            if (--deleter->second == 0)
                delete deleter;
        };

        for (auto chl : mChls)
        {
            chl->asyncSend(data, size, callback);
        }
    }

    void Broadcaster::send(const void * data, u64 size)
    {
        std::atomic<u32> count(u32(mChls.size()));
        std::promise<void> prom;
        std::future<void> fut(prom.get_future());

        std::function<void()> callback = [&]()
        {
            // count down the number of times this callback has been called 
            // and then set the promise once it reaches 0, i.e. all channels
            // have sent the data.
            if (--count == 0)
                prom.set_value();
        };

        for (auto chl : mChls)
        {
            chl->asyncSend(data, size, callback);
        }


        fut.get();
    }

}
