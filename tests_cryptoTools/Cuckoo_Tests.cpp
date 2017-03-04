#include "Cuckoo_Tests.h"

#include "Common.h"
#include  "cryptoTools/Common/CuckooHasher.h"
#include  "cryptoTools/Common/Matrix.h"
#include  "cryptoTools/Crypto/PRNG.h"
using namespace osuCrypto;

namespace tests_cryptoTools
{
    void CuckooHasher_Test_Impl()
    {
        u64 setSize = 10000;

        u64 h = 2;
        std::vector<u64> _hashes(setSize * h + 1);
        MatrixView<u64> hashes(_hashes.begin(), _hashes.end(), h);
        PRNG prng(ZeroBlock);

        for (u64 i = 0; i < hashes.bounds()[0]; ++i)
        {
            for (u64 j = 0; j < h; ++j)
            {
                hashes[i][j] = prng.get<u64>();
            }
        }

        CuckooHasher hashMap0;
        CuckooHasher hashMap1;
        CuckooHasher::Workspace w(1);

        hashMap0.init(setSize, 40, true);
        hashMap1.init(setSize, 40, true);


        for (u64 i = 0; i < setSize; ++i)
        {
            //if (i == 6) hashMap0.print();

            hashMap0.insert(i, hashes[i]);

            std::vector<u64> tt{ i };
            MatrixView<u64> mm(hashes[i].data(), 1, 2);
            hashMap1.insertBatch(tt, mm, w);


            //if (i == 6) hashMap0.print();
            //if (i == 6) hashMap1.print();

            //if (hashMap0 != hashMap1)
            //{
            //    std::cout << i << std::endl;

            //    throw UnitTestFail();
            //}

        }

        if (hashMap0 != hashMap1)
        {
            throw UnitTestFail();
        }
    }

    void CuckooHasher_parallel_Test_Impl()
    {
#ifdef THREAD_SAFE_CUCKOO

        u64 numThreads = 4;
        u64 step = 16;
        u64 setSize = 1 << 16;
        u64 h = 2;
        CuckooHasher hashMap;

        hashMap.init(setSize, 40, true);

        Matrix<u64> hashes(setSize, h);
        PRNG prng(ZeroBlock);
        prng.get(hashes.data(), setSize * h);
        std::vector<std::thread> thrds(numThreads);

        for (u64 t = 0; t < numThreads; ++t)
        {

            thrds[t] = std::thread([&, t]()
            {

                CuckooHasher::Workspace ws(step);

                u64 start = t * setSize / numThreads;
                u64 end = (t + 1) * setSize / numThreads;

                for (u64 i = start; i < end; i += step)
                {
                    u64 ss = std::min(step, setSize - i);
                    std::vector<u64> idx(ss);

                    MatrixView<u64> range(hashes[i].data(), ss, h);

                    for (u64 j = 0; j < ss; ++j)
                        idx[j] = j + i;

                    hashMap.insertBatch(idx, range, ws);
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