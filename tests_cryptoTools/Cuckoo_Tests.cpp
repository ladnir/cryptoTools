#include "Cuckoo_Tests.h"

#include "Common.h"
#include  "cryptoTools/Common/CuckooIndex.h"

#include  "cryptoTools/Common/Matrix.h"
#include  "cryptoTools/Crypto/PRNG.h"
using namespace osuCrypto;

namespace tests_cryptoTools
{
    void CuckooIndex_many_Test_Impl()
    {
        u64 base = 200;
        u64 stepSize = 18;
        u64 setSize = stepSize * base;

        //u64 h = 2;
        std::vector<block> hashes(setSize);
        PRNG prng(ZeroBlock);

        for (u64 i = 0; i < hashes.size(); ++i)
        {
            hashes[i] = prng.get<block>();
        }

        CuckooIndex hashMap0;
        CuckooIndex hashMap1;

        hashMap0.init(setSize, 40);
        hashMap1.init(setSize, 40);


        for (u64 i = 0; i < base; ++i)
        {
            std::vector<u64> tt(stepSize);
            std::vector<block> mm(stepSize);


            for (u64 j = 0; j < stepSize; ++j)
            {
                tt[j] = i * stepSize + j;
                mm[j] = hashes[i * stepSize + j];

                hashMap0.insert(tt[j], mm[j]);
            }

            hashMap1.insert(tt, mm);


            for (u64 j = 0; j < (i + 1) * stepSize; ++j)
            {

                if (hashMap0.find(hashes[j]) != j)
                {
                    std::cout << i << std::endl;
                    throw UnitTestFail();
                }

                if (hashMap1.find(hashes[j]) != j)
                {
                    std::cout << i << std::endl;
                    throw UnitTestFail();
                }
            }
        }

        for (u64 i = 0; i < setSize; ++i)
        {

            if (hashMap0.find(hashes[i]) != i)
            {
                throw UnitTestFail();
            }

            if (hashMap1.find(hashes[i]) != i)
            {
                throw UnitTestFail();
            }
        }
    }

    void CuckooIndex_paramSweep_Test_Impl()
    {
        u64 maxPow = 16;

        for (u64 p = 0; p <= maxPow; ++p)
        {
            u64 setSize = u64(1) << p;
            std::vector<block> hashes(setSize);
            std::vector<u64> idxs(setSize);
            PRNG prng(ZeroBlock);

            for (u64 i = 0; i < hashes.size(); ++i)
            {
                hashes[i] = prng.get<block>();
                idxs[i] = i;
            }

            CuckooIndex hashMap0;
            hashMap0.init(setSize, 40);
            hashMap0.insert(idxs, hashes);
            hashMap0.find(hashes, idxs);

            for (u64 i = 0; i < setSize; ++i)
            {
                if (idxs[i] != i)
                {
                    throw UnitTestFail();
                }
            }
        }
    }

    void CuckooIndex_parallel_Test_Impl()
    {
#ifdef THREAD_SAFE_CUCKOO

        u64 numThreads = 4;
        u64 step = 16;
        u64 setSize = u64(1) << 16;
        //u64 h = 2;
        CuckooIndex hashMap;

        hashMap.init(setSize, 40);

        std::vector<block> hashes(setSize);
        PRNG prng(ZeroBlock);
        prng.get(hashes.data(), setSize);
        std::vector<std::thread> thrds(numThreads);

        for (u64 t = 0; t < numThreads; ++t)
        {

            thrds[t] = std::thread([&, t]()
            {


                u64 start = t * setSize / numThreads;
                u64 end = (t + 1) * setSize / numThreads;

                for (u64 i = start; i < end; i += step)
                {
                    u64 ss = std::min(step, setSize - i);
                    std::vector<u64> idx(ss);

                    //MatrixView<u64> range(hashes[i].data(), ss, h);
                    ArrayView<block> range(hashes.data() + i, ss);
                    for (u64 j = 0; j < ss; ++j)
                        idx[j] = j + i;

                    hashMap.insert(idx, range);
                }
            });
        }

        for (u64 t = 0; t < numThreads; ++t)
            thrds[t].join();

        for (u64 i = 0; i < setSize; ++i)
        {
            if (hashMap.find(hashes[i]) != i)
                throw UnitTestFail();
        }

#endif

    }


}