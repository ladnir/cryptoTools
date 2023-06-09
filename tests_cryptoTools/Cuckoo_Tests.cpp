#include "Cuckoo_Tests.h"

#include "Common.h"
#include  "cryptoTools/Common/CuckooIndex.h"

#include  "cryptoTools/Common/Matrix.h"
#include  "cryptoTools/Crypto/PRNG.h"
#include "SimpleCuckoo.h"
#include <thread>
#include <numeric>

using namespace osuCrypto;

namespace tests_cryptoTools
{


    template<int approxFactor = 3>
    struct ApproxModHasher
    {
        bool mode = 0;
        std::array<u64, approxFactor> mMods, mMasks;
        u64 mMod4, mMod;
        ApproxModHasher(u64 mod)
        {
            if (mode)
            {
                mMod = mod;
                mMod4 = (3ull << log2ceil(mod)) - 1;
            }
            else
            {

                u64 pp = 63;
                u64 i = 0;
                while (pp != ~u64(0) && i < approxFactor)
                {
                    auto mask = 1ull << pp;
                    if (mask & mod)
                    {
                        mMods[i] = mask;
                        mMasks[i] = mask - 1;
                        ++i;
                    }

                    --pp;
                }

                while (i < approxFactor)
                {
                    mMods[i] = 1;
                    mMasks[i] = 0;
                    ++i;
                }

            }

        }

        u64 value() const
        {
            if (mode)
            {
                return mMod;
            }
            else
            {

                auto v = 1ull;
                for (auto m : mMods)
                    v += (m - 1);
                return v;
            }
        }


        u64 mod(block x) const
        {
            if (mode)
            {
                auto xx = x.get<u64>()[0] & (mMod4 - 1);
                while (xx >= mMod)
                    xx -= mMod;

                return xx;
            }
            else
            {

                u64 v = 0ull;
                u64 i = 0;
                for (auto m : mMasks)
                {
                    auto xx = *(u64*)(x.get<u8>().data() + i * 2);
                    auto yy = m & xx;
                    v += yy;
                    ++i;
                }
                return v;
            }

        }
    };

    void CuckooIndex_many_Test_Impl()
    {


        PRNG prng(ZeroBlock);

        //u64 p = 4532;
        //ApproxModHasher<3> m(p);
        //std::vector<u64> counts(p);
        //for (u64 i = 0; i < 1000000; ++i)
        //{
        //    auto x = prng.get<block>();

        //    auto r = m.mod(x);
        //    counts[r]++;
        //}
        //auto p2 = m.value()-1;
        //std::cout << "mm " << p2 << " " << p << std::endl;
        //auto mmin = std::min_element(counts.begin(), counts.begin() + p2);
        //auto mmax = std::max_element(counts.begin(), counts.begin() + p2);
        //auto avg = std::accumulate(counts.begin(), counts.begin() + p2, 0) / double(p2);
        //std::cout << "min " << *mmin << " max " << *mmax << " avg " <<avg<< std::endl;
        ////for (u64 i = 0; i < p2; ++i)
        ////{
        ////    std::cout << i << " ~ " << counts[i] << std::endl;
        ////}















        //return;
        u64 base = 20;
        u64 stepSize = 41;
        u64 setSize = stepSize * base;

        //u64 h = 2;
        std::vector<block> hashes(setSize);

        for (u64 i = 0; i < hashes.size(); ++i)
        {
            hashes[i] = prng.get<block>();

        }

        CuckooIndex<ThreadSafe> hashMap0;
        CuckooIndex<ThreadSafe> hashMap1;

        hashMap0.init(setSize, 40, 0, 3);
        hashMap1.init(setSize, 40, 0, 3);


        //auto mask = hashMap0.mParams.binMask();

        //for (u64 i = 0; i < hashes.size(); ++i)
        //{

        //    auto e = CuckooIndex<>::expand(hashes[i], 3, hashMap0.mNumBins, mask);
        //    for (u64 j = 0; j < 3; ++j)
        //    {
        //        auto h0 = CuckooIndex<>::getHash(hashes[i], j, hashMap0.mNumBins);
        //        auto h1 = CuckooIndex<>::getHash2(e, j, hashMap0.mNumBins);

        //        if (h0 != h1)
        //            throw RTE_LOC;
        //    }

        //}

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

            //std::cout << hashMap0 << std::endl;

            hashMap1.insert(mm, i * stepSize);


            for (u64 j = 0; j < (i + 1) * stepSize; ++j)
            {
                auto f0 = hashMap0.find(hashes[j]);
                if (f0.mInputIdx != j)
                {
                    std::cout << i << " " << j << std::endl;
                    throw UnitTestFail();
                }

                if (hashMap1.find(hashes[j]).mInputIdx != j)
                {
                    std::cout << i << std::endl;
                    throw UnitTestFail();
                }
            }
        }

        for (u64 i = 0; i < setSize; ++i)
        {

            if (hashMap0.find(hashes[i]).mInputIdx != i)
            {
                throw UnitTestFail();
            }

            if (hashMap1.find(hashes[i]).mInputIdx != i)
            {
                throw UnitTestFail();
            }
        }
    }

    void CuckooIndex_paramSweep_Test_Impl()
    {
        u64 maxPow = 18;

        for (u64 p = 0; p <= maxPow; ++p)
        {
            u64 setSize = u64(1) << p;
            std::vector<block> hashes(setSize);
            std::vector<u64> idxs(setSize);
            PRNG prng(OneBlock);

            for (u64 i = 0; i < hashes.size(); ++i)
            {
                hashes[i] = prng.get<block>();
                idxs[i] = i;
            }

            CuckooIndex<NotThreadSafe> hashMap0;
            hashMap0.init(setSize, 40, 0, 3);
            hashMap0.insert(hashes);
            //hashMap0.find(hashes, idxs);

            for (u64 i = 0; i < setSize; ++i)
            {
                idxs[i] = hashMap0.find(hashes[i]).mInputIdx;
                if (idxs[i] != i)
                {
                    throw UnitTestFail();
                }
            }
        }
    }

    void CuckooIndex_parallel_Test_Impl()
    {

        u64 numThreads = 2;
        //u64 step = 1024;
        u64 setSize = u64(1) << 12;
        //u64 h = 2;
        CuckooIndex<ThreadSafe> hashMap;

        hashMap.init(setSize, 40, 0, 3);

        std::vector<block> items(setSize);
        PRNG prng(ZeroBlock);
        prng.get(items.data(), setSize);
        std::vector<std::thread> thrds(numThreads);

        for (u64 t = 0; t < numThreads; ++t)
        {

            thrds[t] = std::thread([&, t]()
                {
                    u64 start = t * setSize / numThreads;
                    u64 end = (t + 1) * setSize / numThreads;
                    span<block> region(items.data() + start, items.data() + end);
                    hashMap.insert(region, ZeroBlock, start);
                });
        }

        for (u64 t = 0; t < numThreads; ++t)
            thrds[t].join();

        hashMap.validate(items, ZeroBlock);
        //for (u64 i = 0; i < setSize; ++i)
        //{
        //    if (hashMap.find() != i)
        //        throw UnitTestFail();
        //}

    }

    //void CuckooIndexVsCuckooHasher()
    //{
    //	u64 /*setSize = 8, */count = 1000;
    //	PRNG prng(_mm_set1_epi64x(0));

    //	double e = 3;
    //	u64 h = 2;

    //	for (auto setSize : { 1 << 8})
    //	{

    //		std::vector<block> hashs(setSize);
    //		std::vector<u64> idxs(setSize);




    //		for (u64 t = 0; t < count; ++t)
    //		{
    //			//if (i % step == 0)std::cout << "\r" << (i / step) << "%" << flush;
    //			prng.mAes.ecbEncCounterMode(prng.mBlockIdx, setSize, (block*)hashs.data());
    //			prng.mBlockIdx += setSize;

    //			//if (t != 14) continue;


    //			CuckooIndex<> c;
    //			SimpleCuckoo cc;
    //			cc.mParams.mBinScaler = c.mParams.mBinScaler = e;
    //			cc.mParams.mNumHashes = c.mParams.mNumHashes = h;
    //			cc.mParams.mStashSize = c.mParams.mStashSize = 400;
    //			cc.mParams.mN = c.mParams.mN = setSize;

    //			u64 stashSize;

    //			for (u64 i = 0; i < setSize; ++i) idxs[i] = i;
    //			cc.init();
    //			c.init(c.mParams);
    //			auto ss = c.mBins.size();


    //			cc.insert(idxs, hashs);
    //			stashSize = cc.stashUtilization();

    //			for (u64 i = 0; i < setSize; ++i) idxs[i] = i;
    //			c.insert(idxs, hashs);
    //			stashSize = c.stashUtilization();


    //			for (u64 i = 0; i < c.mBins.size(); ++i)
    //			{
    //				if (c.mBins[i].mS.mVal != cc.mBins[i].mVal)
    //				{
    //					std::cout << i << " @ " << setSize <<" " << t<< std::endl;

    //					std::cout << "CuckooIndex "; c.print(); std::cout << std::endl;
    //					std::cout << "CuckooSimple "; cc.print(); std::cout << std::endl;

    //					throw std::runtime_error(LOCATION);
    //				}
    //			}
    //		}
    //	}
    //}


}