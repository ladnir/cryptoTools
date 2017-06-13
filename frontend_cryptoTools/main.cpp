
#include "../tests_cryptoTools/UnitTests.h"
#include "Tutorials/Network.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include <cryptoTools/Common/Matrix.h>
#include "cryptoTools/Common/CuckooIndex.h"
using namespace osuCrypto;
#include <sstream>



template<typename T>
std::string diff(T prior, T latter, i64 digits = 3)
{
    std::stringstream out;
    namespace sc = std::chrono;
    out << sc::duration_cast<sc::milliseconds>(latter - prior).count();
/*
    auto const usecs = diff % 1000;
    diff /= 1000;
    auto const msecs = diff % 1000;
    diff /= 1000;
    auto const secs = diff % 60;
    diff /= 60;
    auto const mins = diff % 60;
    diff /= 60;
    auto const hours = diff % 24;
    diff /= 24;
    auto const days = diff;


    bool printed_earlier = false;
    if (days >= 1) {
        printed_earlier = true;
        out << days << "d ";
        persion -= std::log10(days);
    }
    
    if (persion > 0 && hours >= 1) {
        printed_earlier = true;
        out << hours << "h ";

        persion -= std::log10(hours);
    }
    
    if (persion > 0 && mins >= 1) {
        printed_earlier = true;
        out << mins << "m ";
        persion -= std::log10(mins);
    }
    
    
    if (persion > 0 && secs >= 1) {
        printed_earlier = true;
        out << secs << "s ";
        persion -= std::log10(secs);
    }
    
    if (persion > 0 && msecs >= 1) {
        printed_earlier = true;
        out << msecs << "ms ";
        persion -= std::log10(msecs);
    }

    if (persion > 0 ) {
        printed_earlier = true;
        out << usecs << "us ";
        persion -= std::log10(usecs);
    }
*/
    return out.str();
}



void cuckoo(u64 nn, u64 tt)
{
    CuckooIndex<> ci;
    ci.init(nn, 40);
    std::vector<u64> idx(nn);
    std::vector<block> hashes(nn);
    PRNG prng(ZeroBlock);
    

    Timer t;
    auto s = t.setTimePoint("s");
    prng.mAes.ecbEncCounterMode(0, nn, hashes.data());
    for (u64 i = 0; i < nn; ++i)
    {
        idx[i] = i;
    }

    std::vector<std::thread> thrds(tt);
    for (u64 t = 0; t < tt; ++t)
    {
        thrds[t] = std::thread([&,t]()
        {
            auto s = nn * t / tt;
            auto e = nn * (t+1) / tt;
            ArrayView<u64> range(idx.data() + s, idx.data() + e);
            ArrayView<block> rangeh(hashes.data() + s, hashes.data() + e);

            ci.insert(range, rangeh);
        });
    }
    for (u64 t = 0; t < tt; ++t)
    {
        thrds[t].join();
    }

    auto e = t.setTimePoint("s");


    std::cout << "n" << nn << "  t" << tt <<"  "<< diff(s, e) << std::endl;
}


int main(int argc, char** argv)
{
    //for (auto p : { 16, 20, 24 })
    //{
    //    for (auto t : { 1,4,16,64 })
    //    {
    //        auto n = 1 << p;
    //        cuckoo(n, t);
    //    }
    //}



/*
    IOService ios;
    Endpoint ep0(ios, "localhost", EpMode::Server, "s");
    Endpoint ep1(ios, "localhost", EpMode::Client, "s");

    Channel c0 = ep0.addChannel("c");
    Channel c1 = ep1.addChannel("c");

    std::vector<std::pair<double, double>> comms
    {
        {6804 ,9216  },
        {7935 ,4608  },
        {3402 ,9216  },
        {1890 ,18432 },
        {3016 ,18432 },
        {750  ,8704  },
        {1250 ,4352  },
        {464  ,9216  },
        {928  ,4608  },
        {1856 ,2304  },
        {3712 ,1152  },
        {232  ,2304  },
        {464  ,1152  },
        {928  ,576   }

    };



    std::vector<u8> data(18432 * 1024);







    c0.send(data.data(), 1);
    c1.recv(data.data(), 1);


    for (auto com : comms)
    {
        Timer t;
        auto s = t.setTimePoint("s");
        c0.asyncSend(data.data(), com.first * 1024);
        c1.recv(data.data(), com.first * 1024);
        c0.asyncSend(data.data(), com.second * 1024);
        c1.recv(data.data(), com.second * 1024);
        auto e = t.setTimePoint("e");

        std::cout << "comm " << com.first << " " << com.second << "  " << diff(s, e) << std::endl;
    }
*/
       
    tests_cryptoTools::tests_all();

}