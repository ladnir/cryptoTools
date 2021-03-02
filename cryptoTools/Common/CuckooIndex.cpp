#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Log.h>
#include <numeric>
#include <random>
#include <algorithm>
#include <mutex>

#define CUCKOO_BATCH_SIZE 8

namespace osuCrypto
{

    // parameters for k=2 hash functions, 2^n items, and statistical security 40
    CuckooParam k2n32s40CuckooParam{ 4, 2.4, 2, u64(1) << 32 };
    CuckooParam k2n30s40CuckooParam{ 4, 2.4, 2, u64(1) << 30 };
    CuckooParam k2n28s40CuckooParam{ 2, 2.4, 2, u64(1) << 28 };
    CuckooParam k2n24s40CuckooParam{ 2, 2.4, 2, u64(1) << 24 };
    CuckooParam k2n20s40CuckooParam{ 2, 2.4, 2, u64(1) << 20 };
    CuckooParam k2n16s40CuckooParam{ 3, 2.4, 2, u64(1) << 16 };
    CuckooParam k2n12s40CuckooParam{ 5, 2.4, 2, u64(1) << 12 };
    CuckooParam k2n08s40CuckooParam{ 8, 2.4, 2, u64(1) << 8 };

    // not sure if this needs a stash of 40, but should be safe enough.
    CuckooParam k2n07s40CuckooParam{ 40, 2.4, 2, 1 << 7 };
    CuckooParam k2n06s40CuckooParam{ 40, 2.4, 2, 1 << 6 };
    CuckooParam k2n05s40CuckooParam{ 40, 2.4, 2, 1 << 5 };
    CuckooParam k2n04s40CuckooParam{ 40, 2.4, 2, 1 << 4 };
    CuckooParam k2n03s40CuckooParam{ 40, 2.4, 2, 1 << 3 };
    CuckooParam k2n02s40CuckooParam{ 40, 2.4, 2, 1 << 2 };
    CuckooParam k2n01s40CuckooParam{ 40, 2.4, 2, 1 << 1 };




    template<CuckooTypes Mode>
    CuckooIndex<Mode>::CuckooIndex()
        :mTotalTries(0)
    { }

    template<CuckooTypes Mode>
    CuckooIndex<Mode>::~CuckooIndex()
    {
    }

    template<CuckooTypes Mode>
    bool CuckooIndex<Mode>::operator==(const CuckooIndex& cmp) const
    {
        if (mBins.size() != cmp.mBins.size())
            throw std::runtime_error("");

        if (mStash.size() != cmp.mStash.size())
            throw std::runtime_error("");



        for (u64 i = 0; i < mBins.size(); ++i)
        {
            if (mBins[i].load() != cmp.mBins[i].load())
            {
                return false;
            }
        }

        for (u64 i = 0; i < mStash.size(); ++i)
        {
            if (mStash[i].load() != cmp.mStash[i].load())
            {
                return false;
            }
        }

        return true;
    }

    template<CuckooTypes Mode>
    bool CuckooIndex<Mode>::operator!=(const CuckooIndex& cmp) const
    {
        return !(*this == cmp);
    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::print() const
    {

        std::cout << "Cuckoo Hasher  " << std::endl;


        for (u64 i = 0; i < mBins.size(); ++i)
        {
            std::cout << "Bin #" << i;

            if (mBins[i].isEmpty())
            {
                std::cout << " - " << std::endl;
            }
            else
            {
                std::cout << "    c_idx=" << mBins[i].idx() << "  hIdx=" << mBins[i].hashIdx() << std::endl;

            }

        }
        for (u64 i = 0; i < mStash.size() && mStash[i].isEmpty() == false; ++i)
        {
            std::cout << "Bin #" << i;

            if (mStash[i].isEmpty())
            {
                std::cout << " - " << std::endl;
            }
            else
            {
                std::cout << "    c_idx=" << mStash[i].idx() << "  hIdx=" << mStash[i].hashIdx() << std::endl;

            }

        }
        std::cout << std::endl;

    }

    template<CuckooTypes Mode>
    CuckooParam CuckooIndex<Mode>::selectParams(const u64& n, const u64& statSecParam, const u64& stashSize, const u64& hh)
    {
        double nn = std::log2(n);

        auto h = hh ? hh : 3;

        if (stashSize == 0 && h == 3)
        {
            // parameters that have been experimentally determined.
            double aMax = 123.5;
            double bMax = -130;
            double aSD = 2.3;
            double bSD = 2.18;
            double aMean = 6.3;
            double bMean = 6.45;

            // slope = 123.5 - some small terms when nn < 12.
            double a = aMax / 2 * (1 + erf((nn - aMean) / (aSD * std::sqrt(2))));
            // y-intercept = -130 - nn + some small terms when nn < 12.
            double b = bMax / 2 * (1 + erf((nn - bMean) / (bSD * std::sqrt(2)))) - nn;
            // small terms follow the integrel of the normal distribution.

            // we have the statSecParam = a e + b, where e = |cuckoo|/|set| is the expenation factor
            // therefore we have that
            //
            //   e = (statSecParam - b) / a
            //
            return CuckooParam{ 0,(statSecParam - b) / a, 3, n };
        }
        else if (h == 2)
        {
            // parameters that have been experimentally determined.
            double
                a = -0.8,
                b = 3.3,
                c = 2.5,
                d = 14,
                f = 5,
                g = 0.65;

            // for e > 8,   statSecParam = (1 + 0.65 * stashSize) (b * std::log2(e) + a + nn).
            // for e < 8,   statSecParam -> 0 at e = 2. This is what the pow(...) does...
            auto sec = [&](double e) { return (1 + g * stashSize) * (b * std::log2(e) + a + nn - (f * nn + d) * std::pow(e, -c)); };

            // increase e util we have large enough security.
            double e = 1;
            double s = 0;
            while (s < statSecParam)
            {
                e += 1;
                s = sec(e);
            }

            return CuckooParam{ 0, e, 2, n };
        }

        throw std::runtime_error(LOCATION);

    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::init(const u64& n, const u64& statSecParam, u64 stashSize, u64 h)
    {
        init(selectParams(n, statSecParam, stashSize, h));
    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::init(const CuckooParam& params)
    {
        mParams = params;

        if (CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT < params.mNumHashes)
            throw std::runtime_error("parameters exceeded the maximum number of hash functions are are supported. see getHash(...); " LOCATION);

        mHashes.resize(mParams.mN, AllOneBlock);
        u64 binCount = u64(mParams.mBinScaler * mParams.mN);

        //binCount = ;

        mBins.resize(binCount);
        mStash.resize(mParams.mStashSize);
        mNumBins = binCount;
        mNumBinMask = (1ull << log2ceil(binCount)) - 1;
        //mPrng.SetSeed(ZeroBlock);
        //mRandHashIdx.resize(100);
        //for (u64 i = 1; i < mRandHashIdx.size(); ++i)
        //{
        //	if (mParams.mRandomized)
        //	{
        //		mRandHashIdx[i] = mPrng.get<u8>() % (mParams.mNumHashes - 1);
        //		if (mRandHashIdx[i] >= mRandHashIdx[i - 1])
        //			++mRandHashIdx[i];
        //	}
        //	else
        //	{
        //		mRandHashIdx[i] = i % mParams.mNumHashes;
        //	}
        //}
    }


    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::insert(span<block> items, block hashingSeed, u64 startIdx)
    {
        //if (Mode == CuckooTypes::ThreadSafe) std::cout << "ThreadSafe" << std::endl;
        //if (Mode == CuckooTypes::NotThreadSafe) std::cout << "NotThreadSafe" << std::endl;

        std::array<block, 16> hashs;
        std::array<u64, 16> idxs;
        AES hasher(hashingSeed);

        for (u64 i = 0; i < u64(items.size()); i += u64(hashs.size()))
        {
            auto min = std::min<u64>(items.size() - i, hashs.size());

            hasher.ecbEncBlocks(items.data() + i, min, hashs.data());

            for (u64 j = 0, jj = i; j < min; ++j, ++jj)
            {
                idxs[j] = jj + startIdx;
                hashs[j] = hashs[j] ^ items[jj];

                //if(jj < 1) std::cout<< IoStream::lock << "item[" << jj << "] = " <<items[jj]<<" -> " << hashs[j] << std::endl << IoStream::unlock;
            }

            insert(min, idxs.data(), hashs.data());
        }
    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::insert(span<block> items, u64 startIdx)
    {
        std::array<u64, 16> idxs;

        for (u64 i = 0; i < u64(items.size()); i += u64(idxs.size()))
        {

            auto min = std::min<u64>(items.size() - i, idxs.size());
            for (u64 j = 0, jj = i; j < min; ++j, ++jj)
            {
                idxs[j] = jj + startIdx;
            }

            insert(min, idxs.data(), items.data() + i);
        }
    }


    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::insert(const u64& inputIdx, const block& hashs)
    {
        insert(1, &inputIdx, &hashs);
    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::insert(
        span<u64> inputIdxs,
        span<block> hashs)
    {
#ifndef NDEBUG
        if (inputIdxs.size() != hashs.size())
            throw std::runtime_error("" LOCATION);
#endif

        insert(inputIdxs.size(), inputIdxs.data(), hashs.data());
    }

    template<CuckooTypes Mode>
    u8 CuckooIndex<Mode>::minCollidingHashIdx(u64 target, block& hashes, u8 numHashFunctions,
        u64 numBins)
    {
        for (u64 i = 0; i < numHashFunctions; ++i)
        {
            if (target == getHash2(hashes, i, numBins))
                return u8(i);
        }
        return -1;
    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::insert(
        const u64& sizeMaster,
        const u64* inputIdxsMaster,
        const block* hashs)
    {
        const u64 nullIdx = (u64(-1) >> 8);
        std::array<u64, CUCKOO_BATCH_SIZE> curHashIdxs, curAddrs,
            inputIdxs, tryCounts;


        u64 i = 0;
        for (; i < CUCKOO_BATCH_SIZE; ++i)
        {
            if (i < sizeMaster)
            {

                inputIdxs[i] = inputIdxsMaster[i];
#ifndef NDEBUG
                if (neq(mHashes[inputIdxs[i]], AllOneBlock))
                {
                    std::cout << IoStream::lock << "cuckoo index " << inputIdxs[i] << " already inserted" << std::endl << IoStream::unlock;
                    throw std::runtime_error(LOCATION);
                }
#endif // ! NDEBUG

                mHashes[inputIdxs[i]] = expand(hashs[i], 3, mNumBins, mNumBinMask);
                curHashIdxs[i] = 0;
                tryCounts[i] = 0;
            }
            else
            {
                inputIdxs[i] = nullIdx;
            }
        }


#if CUCKOO_BATCH_SIZE == 8
        if (sizeMaster > 8 && mParams.mNumHashes == 3)
        {
            while (i < sizeMaster - 8)
            {

                // this data fetch can be slow (after the first loop).
                // As such, lets do several fetches in parallel.
                
                auto h0 = (u8*)&mHashes[inputIdxs[0]];
                auto h1 = (u8*)&mHashes[inputIdxs[1]];
                auto h2 = (u8*)&mHashes[inputIdxs[2]];
                auto h3 = (u8*)&mHashes[inputIdxs[3]];
                auto h4 = (u8*)&mHashes[inputIdxs[4]];
                auto h5 = (u8*)&mHashes[inputIdxs[5]];
                auto h6 = (u8*)&mHashes[inputIdxs[6]];
                auto h7 = (u8*)&mHashes[inputIdxs[7]];


                curAddrs[0] = (*(u64*)(h0 + curHashIdxs[0] * 5)) & 1099511627775ull;
                curAddrs[1] = (*(u64*)(h1 + curHashIdxs[1] * 5)) & 1099511627775ull;
                curAddrs[2] = (*(u64*)(h2 + curHashIdxs[2] * 5)) & 1099511627775ull;
                curAddrs[3] = (*(u64*)(h3 + curHashIdxs[3] * 5)) & 1099511627775ull;
                curAddrs[4] = (*(u64*)(h4 + curHashIdxs[4] * 5)) & 1099511627775ull;
                curAddrs[5] = (*(u64*)(h5 + curHashIdxs[5] * 5)) & 1099511627775ull;
                curAddrs[6] = (*(u64*)(h6 + curHashIdxs[6] * 5)) & 1099511627775ull;
                curAddrs[7] = (*(u64*)(h7 + curHashIdxs[7] * 5)) & 1099511627775ull;


                // same thing here, this fetch is slow. Do them in parallel.
                //u64 newVal0 = inputIdxs[0] | (curHashIdxs[0] << 56);
                //oldVals[i] = 
                mBins[curAddrs[0]].swap(inputIdxs[0], curHashIdxs[0]);
                mBins[curAddrs[1]].swap(inputIdxs[1], curHashIdxs[1]);
                mBins[curAddrs[2]].swap(inputIdxs[2], curHashIdxs[2]);
                mBins[curAddrs[3]].swap(inputIdxs[3], curHashIdxs[3]);
                mBins[curAddrs[4]].swap(inputIdxs[4], curHashIdxs[4]);
                mBins[curAddrs[5]].swap(inputIdxs[5], curHashIdxs[5]);
                mBins[curAddrs[6]].swap(inputIdxs[6], curHashIdxs[6]);
                mBins[curAddrs[7]].swap(inputIdxs[7], curHashIdxs[7]);


                for (u64 j = 0; j < 8; ++j)
                {
                    if (inputIdxs[j] == nullIdx)
                    {
                        inputIdxs[j] = inputIdxsMaster[i];
                        mHashes[inputIdxs[j]] = expand(hashs[i], 3,mNumBins, mNumBinMask);
                        curHashIdxs[j] = 0;
                        tryCounts[j] = 0;
                        ++i;
                    }
                    else
                    {
                        if (tryCounts[j] != mReinsertLimit)
                        {
                            curHashIdxs[j] = (1 + curHashIdxs[j]) % 3;
                            ++tryCounts[j];
                        }
                        else
                        {

                            u64 k = ~u64(0);
                            do
                            {
                                ++k;
                                if (k == mStash.size())
                                {
                                    std::cout << "cuckoo stash overflow" << std::endl;
                                    throw RTE_LOC;
                                }
                            }                     while (mStash[k].isEmpty() == false);
                            mStash[k].swap(inputIdxs[j], curHashIdxs[j]);

                            inputIdxs[j] = inputIdxsMaster[i];
                            mHashes[inputIdxs[j]] = expand(hashs[i], 3, mNumBins, mNumBinMask);
                            curHashIdxs[j] = 0;
                            tryCounts[j] = 0;
                            ++i;
                        }
                    }
                }
            }
        }
#endif
        for (u64 j = 0; j < CUCKOO_BATCH_SIZE; ++j)
        {

            if (inputIdxs[j] != nullIdx)
            {
                insertOne(inputIdxs[j], curHashIdxs[j], tryCounts[j]);
            }
        }


        while (i < sizeMaster)
        {
            mHashes[inputIdxsMaster[i]] = expand(hashs[i], mParams.mNumHashes, mNumBins, mNumBinMask);
            insertOne(inputIdxsMaster[i], 0, 0);
            ++i;
        }
    }

    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::insertOne(
        u64 inputIdx, u64 curHashIdx, u64 tryIdx)
    {
        const u64 nullIdx = (u64(-1) >> 8);
        while (true)
        {
            auto curAddr = getHash(inputIdx, curHashIdx);
            mBins[curAddr].swap(inputIdx, curHashIdx);

            if (inputIdx == nullIdx)
            {
                return;
            }
            else
            {
                if (tryIdx != mReinsertLimit)
                {
                    curHashIdx = (1 + curHashIdx) % mParams.mNumHashes;
                    ++tryIdx;
                }
                else
                {
                    u64 k = ~u64(0);
                    do
                    {
                        ++k;
                        if (k == mStash.size())
                        {
                            std::cout << "cuckoo stash overflow" << std::endl;
                            throw RTE_LOC;
                        }
                    }                     
                    while (mStash[k].isEmpty() == false);
                    mStash[k].swap(inputIdx, curHashIdx);
                    return;
                }
            }
        }
    }

    template<CuckooTypes Mode>
    u64 CuckooIndex<Mode>::getHash(const u64& inputIdx, const u64& hashIdx)
    {
        //return CuckooIndex<Mode>::getHash3(mHashes[inputIdx], hashIdx, mNumBinMask);
        return CuckooIndex<Mode>::getHash2(mHashes[inputIdx], hashIdx, mNumBins);
    }


    template <typename T, unsigned int b>
    T
        rotl(T v)
    {
        static_assert(std::is_integral<T>::value, "rotate of non-integral type");
        static_assert(!std::is_signed<T>::value, "rotate of signed type");
        constexpr unsigned int num_bits{ std::numeric_limits<T>::digits };
        static_assert(0 == (num_bits & (num_bits - 1)), "rotate value bit length not power of two");
        constexpr unsigned int count_mask{ num_bits - 1 };
        constexpr unsigned int mb{ b & count_mask };
        using promoted_type = typename std::common_type<int, T>::type;
        using unsigned_promoted_type = typename std::make_unsigned<promoted_type>::type;
        return ((unsigned_promoted_type{ v } << mb)
            | (unsigned_promoted_type{ v } >> (-mb & count_mask)));
    }


    template<CuckooTypes Mode>
    block CuckooIndex<Mode>::expand(const block& hash, const u8& numHash, const u64& num_bins,const u64& binMask)
    {

        static_assert(CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT < 5,
            "here we assume that we dont overflow the 16 byte 'block hash'. "
            "To assume that we can have at most 4 has function, i.e. we need  2*hashIdx + sizeof(u64) < sizeof(block)");

        assert(numHash <= 3);
        //static const u64 mask = (1ull << 40) - 1;
        auto& bytes = hash.as<const u8>();
        u64 h0 = *(u64*)bytes.data();
        u64 h1 = *(u64*)(bytes.data() + 4);
        u64 h2 = *(u64*)(bytes.data() + 8);

        while ((binMask & h0) >= num_bins)
            h0 = rotl<u64, 7>(h0);
        while ((binMask & h1) >= num_bins)
            h1 =rotl<u64, 7>(h1);
        while ((binMask & h2) >= num_bins)
            h2 = rotl<u64, 7>(h2);

        h0 = (binMask & h0);
        h1 = (binMask & h1);
        h2 = (binMask & h2);

        //h0 = h0 % num_bins;
        //h1 = h1 % num_bins;
        //h2 = h2 % num_bins;

        if (h0 >= num_bins)
            throw RTE_LOC;
        if (h1 >= num_bins)
            throw RTE_LOC;
        if (h2 >= num_bins)
            throw RTE_LOC;

        block ret = ZeroBlock;
        std::memcpy(&ret.as<u8>()[0], &h0, 5);
        std::memcpy(&ret.as<u8>()[5], &h1, 5);
        std::memcpy(&ret.as<u8>()[10], &h2, 5);
        return ret;
    }


    template<CuckooTypes Mode>
    u64 CuckooIndex<Mode>::getHash2(const block& hash, const u8& hashIdx, const u64& num_bins)
    {

        static_assert(CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT < 5,
            "here we assume that we dont overflow the 16 byte 'block hash'. "
            "To assume that we can have at most 4 has function, i.e. we need  2*hashIdx + sizeof(u64) < sizeof(block)");
        //AES aes(block(0, hashIdx));
        //auto h = aes.ecbEncBlock(hash);
        //return (*(u64*)&h) % num_bins;
        auto rr = (*(u64*)&hash.as<u8>()[hashIdx * 5]) & 1099511627775ull;
        //if (rr >= num_bins)
        //    throw RTE_LOC;
        return rr;
        //return mod64(*(u64*)(((u8*)&hash) + (2 * hashIdx)), num_bins);
    }

    template<CuckooTypes Mode>
    typename CuckooIndex<Mode>::FindResult CuckooIndex<Mode>::find(const block& hashes_)
    {
        auto hashes = expand(hashes_, mParams.mNumHashes, mNumBins, mNumBinMask);
        if (mParams.mNumHashes == 2)
        {
            std::array<u64, 2>  addr{
                getHash2(hashes, 0, mNumBins),
                getHash2(hashes, 1, mNumBins) };

            std::array<u64, 2> val{
                mBins[addr[0]].load(),
                mBins[addr[1]].load() };

            if (val[0] != u64(-1))
            {
                u64 itemIdx = val[0] & (u64(-1) >> 8);

                bool match = eq(mHashes[itemIdx], hashes);

                if (match) return { itemIdx, addr[0] };
            }

            if (val[1] != u64(-1))
            {
                u64 itemIdx = val[1] & (u64(-1) >> 8);

                bool match = eq(mHashes[itemIdx], hashes);

                if (match) return { itemIdx, addr[1] };
            }


            // stash
            u64 i = 0;
            while (i < mStash.size() && mStash[i].isEmpty() == false)
            {
                u64 val = mStash[i].load();
                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = eq(mHashes[itemIdx], hashes);

                    if (match)
                    {
                        return { itemIdx, i + mBins.size() };
                    }
                }

                ++i;
            }

        }
        else
        {

            for (u64 i = 0; i < mParams.mNumHashes; ++i)
            {
                u64 xrHashVal = getHash2(hashes, i, mNumBins);
                auto addr = (xrHashVal) % mBins.size();


                u64 val = mBins[addr].load();

                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = eq(mHashes[itemIdx], hashes);

                    if (match)
                    {
                        return { itemIdx, addr };
                    }
                }
            }

            u64 i = 0;
            while (i < mStash.size() && mStash[i].isEmpty() == false)
            {
                u64 val = mStash[i].load();

                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = eq(mHashes[itemIdx], hashes);

                    if (match)
                    {
                        return { itemIdx, i + mBins.size() };
                    }
                }

                ++i;
            }
        }

        return { ~0ull,~0ull };
    }


    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::find(
        span<block> hashes,
        span<u64> idxs)
    {
#ifndef NDEBUG
        if (hashes.size() != idxs.size())
            throw std::runtime_error(LOCATION);
#endif

        find(hashes.size(), hashes.data(), idxs.data());
    }




    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::find(const u64& numItemsMaster, const block* hashesMaster, const u64* idxsMaster)
    {
        std::array<std::array<u64, 2>, CUCKOO_BATCH_SIZE> findVal;
        std::array<u64, CUCKOO_BATCH_SIZE> idxs;
        //std::array<block, BATCH_SIZE> idxs;


        for (u64 step = 0; step < (numItemsMaster + findVal.size() - 1) / findVal.size(); ++step)
        {
            auto numItems = std::min<u64>(numItemsMaster - findVal.size() * step, findVal.size());

            //auto idxs = idxsMaster + step * findVal.size();
            memcpy(idxs.data(), idxsMaster + step * findVal.size(), sizeof(u64) * CUCKOO_BATCH_SIZE);
            auto hashes = hashesMaster + step * findVal.size();

            if (mParams.mNumHashes == 2)
            {
                std::array<u64, 2>  addr;

                for (u64 i = 0; i < numItems; ++i)
                {
                    idxs[i] = -1;

                    addr[0] = getHash2(hashes[i], 0, mNumBins);
                    addr[1] = getHash2(hashes[i], 1, mNumBins);

                    findVal[i][0] = mBins[addr[0]].load();
                    findVal[i][1] = mBins[addr[1]].load();
                }

                for (u64 i = 0; i < numItems; ++i)
                {
                    if (findVal[i][0] != u64(-1))
                    {
                        u64 itemIdx = findVal[i][0] & (u64(-1) >> 8);
                        bool match = eq(mHashes[itemIdx], hashes[i]);
                        if (match)
                        {
                            idxs[i] = itemIdx;
                        }
                    }

                    if (findVal[i][1] != u64(-1))
                    {
                        u64 itemIdx = findVal[i][1] & (u64(-1) >> 8);
                        bool match = eq(mHashes[itemIdx], hashes[i]);
                        if (match) idxs[i] = itemIdx;
                    }
                }

                // stash

                u64 i = 0;
                while (i < mStash.size() && mStash[i].isEmpty() == false)
                {
                    u64 val = mStash[i].load();
                    if (val != u64(-1))
                    {
                        u64 itemIdx = val & (u64(-1) >> 8);

                        for (u64 j = 0; j < numItems; ++j)
                        {
                            bool match = eq(mHashes[itemIdx], hashes[i]);
                            if (match) idxs[j] = itemIdx;
                        }
                    }

                    ++i;
                }
            }
            else
            {
                throw std::runtime_error("not implemented");
            }
        }

    }


    template<CuckooTypes Mode>
    void CuckooIndex<Mode>::validate(span<block> inputs, block hashingSeed)
    {
        AES hasher(hashingSeed);
        u64 insertCount = 0;

        for (u64 i = 0; i < u64(inputs.size()); ++i)
        {

            block hash = hasher.ecbEncBlock(inputs[i]) ^ inputs[i];

            hash = expand(hash, mParams.mNumHashes, mNumBins, mNumBinMask);

            if (neq(hash, mHashes[i]))
                throw std::runtime_error(LOCATION);

            if (neq(mHashes[i], AllOneBlock))
            {
                ++insertCount;
                u64 matches(0);
                std::vector<u64> hashes(mParams.mNumHashes);
                for (u64 j = 0; j < mParams.mNumHashes; ++j)
                {
                    auto h = hashes[j] = getHash(i, j);
                    auto duplicate = (std::find(hashes.begin(), hashes.begin() + j, h) != (hashes.begin() + j));

                    if (duplicate == false && mBins[h].isEmpty() == false && mBins[h].idx() == i)
                    {
                        ++matches;
                    }
                }

                if (matches != 1)
                    throw std::runtime_error(LOCATION);
            }
        }

        u64 nonEmptyCount(0);
        for (u64 i = 0; i < mBins.size(); ++i)
        {
            if (mBins[i].isEmpty() == false)
                ++nonEmptyCount;
        }

        if (nonEmptyCount != insertCount)
            throw std::runtime_error(LOCATION);
    }

    template<CuckooTypes Mode>
    u64 CuckooIndex<Mode>::stashUtilization() const
    {
        u64 i = 0;
        while (i < mStash.size() && mStash[i].isEmpty() == false)
        {
            ++i;
        }

        return i;
    }


    //    bool CuckooIndex<Mode>::Bin::isEmpty() const
    //    {
    //        return mVal == u64(-1);
    //    }
    //
    //    u64 CuckooIndex<Mode>::Bin::idx() const
    //    {
    //        return mVal  & (u64(-1) >> 8);
    //    }
    //
    //    u64 CuckooIndex<Mode>::Bin::hashIdx() const
    //    {
    //        return mVal >> 56;
    //    }
    //
    //    void CuckooIndex<Mode>::Bin::swap(u64 & idx, u64 & hashIdx)
    //    {
    //        u64 newVal = idx | (hashIdx << 56);
    //#ifdef THREAD_SAFE_CUCKOO
    //        u64 oldVal = mVal.exchange(newVal, std::memory_order_relaxed);
    //#else
    //        u64 oldVal = mVal;
    //        mVal = newVal;
    //#endif
    //        if (oldVal == u64(-1))
    //        {
    //            idx = hashIdx = u64(-1);
    //        }
    //        else
    //        {
    //            idx = oldVal & (u64(-1) >> 8);
    //            hashIdx = oldVal >> 56;
    //        }
    //    }


    template class CuckooIndex<ThreadSafe>;
    template class CuckooIndex<NotThreadSafe>;
}
