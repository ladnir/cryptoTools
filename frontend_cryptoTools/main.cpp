
#include "../tests_cryptoTools/UnitTests.h"
#include "Tutorials/Network.h"

#include <cryptoTools/Common/Matrix.h>
using namespace osuCrypto;
#include <cryptoTools/Common/CuckooMap.h>
#include <sstream>

template<typename T>
std::string diff(T prior, T latter)
{
    std::stringstream out;
    namespace sc = std::chrono;
    auto diff = sc::duration_cast<sc::microseconds>(latter - prior).count();

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
    }
    else if (hours >= 1) {
        printed_earlier = true;
        out << hours << "h ";
    }
    else if (mins >= 1) {
        printed_earlier = true;
        out << mins << "m ";
    }
    else if (secs >= 1) {
        printed_earlier = true;
        out << secs << "s ";
    }
    else if (msecs >= 1) {
        printed_earlier = true;
        out << msecs << "ms ";
    }
    else /*if (usecs >= 1)*/ {
        printed_earlier = true;
        out << usecs << "us ";
    }

    return out.str();
}



int main(int argc, char** argv)
{
    {

        u64 maxPow = 32;
        PRNG prng(ZeroBlock);
        for (u64 p = 0; p <= maxPow; ++p)
        {
            u64 n = 1 << p;

            std::vector<u64> idx(n);
            std::vector<block> h(n);
            prng.get(h.data(), h.size());
            //std::vector<std::string> ss(n);
            //std::vector<Optional<u64&>> f(n);
            for (u64 i = 0; i < n; ++i)
            {
                idx[i] = i;
            }

            Timer t;
            auto s = t.setTimePoint("s");
            {
                details::BigCuckooMap<u64, u64> map(n);
                map.insert(idx, idx);
                //map.find(idx, f);
            }
            auto e = t.setTimePoint("e");

            //auto s2 = t.setTimePoint("s");
            ////{
            ////    details::SmallCuckooMap<u64, u64> map(n);
            ////    map.insert(idx, idx);
            ////    map.find(idx, f);
            ////}
            //auto e2 = t.setTimePoint("e");


            auto s3 = t.setTimePoint("s");
            {
                //CuckooMap2<u64, u64> map(n);
                CuckooHasher map;
                map.init(n, 40);

                map.insert(idx, h);
                //map.find(idx, f);
            }
            auto e3 = t.setTimePoint("e");




            auto s4 = t.setTimePoint("s");
            {
                //CuckooMap2<u64, u64> map(n);

                CuckooHasher map;
                map.init(n, 40);

                for (u64 i = 0; i < n; ++i)
                    map.insert(idx[i], h[i]);

                //for (u64 i = 0; i < n; ++i)
                //    map.find(idx[i]);
            }

            auto e4 = t.setTimePoint("e");

            //auto tb = (e - s).count();
            //auto ts = (e2 - s2).count();
            auto tc = (e3 - s3).count();
            auto td = (e4 - s4).count();

            auto tBig = diff(s, e);
            //auto tSmall = diff(s2, e2);
            auto tC = diff(s3, e3);
            auto tD = diff(s4, e4);
            std::cout << "Big " << n << "  " << tBig << "  "/* << tSmall << "  "*/ << tC << "  " << tD /*<< "  " << (ts < tb ? "small" : "big") */ << std::endl;

        }
    }
    //tests_cryptoTools::tests_all();

}