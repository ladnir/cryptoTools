#include <cryptoTools/Common/CuckooHasher.h>
#include <cryptoTools/Crypto/sha1.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Log.h>
#include <numeric>
#include <random>


#define BATCH_SIZE 8

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


    CuckooHasher::CuckooHasher()
        :mTotalTries(0)
    { }

    CuckooHasher::~CuckooHasher()
    {
    }

    bool CuckooHasher::operator==(const CuckooHasher & cmp) const
    {
        if (mBins.size() != cmp.mBins.size())
            throw std::runtime_error("");

        if (mStash.size() != cmp.mStash.size())
            throw std::runtime_error("");



        for (u64 i = 0; i < mBins.size(); ++i)
        {
            if (mBins[i].mVal != cmp.mBins[i].mVal)
            {
                return false;
            }
        }

        for (u64 i = 0; i < mStash.size(); ++i)
        {
            if (mStash[i].mVal != cmp.mStash[i].mVal)
            {
                return false;
            }
        }

        return true;
    }

    bool CuckooHasher::operator!=(const CuckooHasher & cmp) const
    {
        return !(*this == cmp);
    }

    void CuckooHasher::print() const
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

    void CuckooHasher::init(const u64& n, const u64& statSecParam, bool multiThreaded)
    {
        if (statSecParam && statSecParam != 40) throw std::runtime_error("not implemented");

        //std::cout << "Params: " << n << " " << std::log2(n) << std::endl;

        if (n <= 1 << 1)
            mParams = k2n01s40CuckooParam;
        else if (n <= u64(1) << 2)
            mParams = k2n02s40CuckooParam;
        else if (n <= u64(1) << 3)
            mParams = k2n03s40CuckooParam;
        else if (n <= u64(1) << 4)
            mParams = k2n04s40CuckooParam;
        else if (n <= u64(1) << 5)
            mParams = k2n05s40CuckooParam;
        else if (n <= u64(1) << 6)
            mParams = k2n06s40CuckooParam;
        else if (n <= u64(1) << 7)
            mParams = k2n07s40CuckooParam;
        else if (n <= u64(1) << 8)
            mParams = k2n08s40CuckooParam;
        else if (n <= u64(1) << 12)
            mParams = k2n12s40CuckooParam;
        else if (n <= u64(1) << 16)
            mParams = k2n16s40CuckooParam;
        else if (n <= u64(1) << 20)
            mParams = k2n20s40CuckooParam;
        else if (n <= u64(1) << 24)
            mParams = k2n24s40CuckooParam;
        else if (n <= u64(1) << 28)
            mParams = k2n28s40CuckooParam;
        else if (n <= u64(1) << 30)
            mParams = k2n30s40CuckooParam;
        else if (n <= u64(1) << 32)
            mParams = k2n32s40CuckooParam;
        else
        {
            std::cout << "Failed to find cuckoo parameters large enough  " << n << " " << std::log2(n) << "\n" LOCATION << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            throw std::runtime_error("not implemented " LOCATION);
        }


        //mHashes.resize(n, AllOneBlock);
        //memset(mHashes.data(), -1, mHashes.size() * sizeof(u64));


        u64 binCount = u64(mParams.mBinScaler * (statSecParam ? n : mParams.mN));

        mBins.resize(binCount);
        mStash.resize(mParams.mStashSize);
    }

    void CuckooHasher::insert(const u64& inputIdx, const block& hashs)
    {

        insert(1, &inputIdx, &hashs);

        //if (neq(mHashes[inputIdx], AllOneBlock))
        //{
        //    throw std::runtime_error("inputIdx already inserted");
        //}
        //mHashes[inputIdx] = hashs;
        //insertHelper(inputIdx, 0, 0);
    }

    void CuckooHasher::insert(
        ArrayView<u64> inputIdxs,
        ArrayView<block> hashs)
    {
#ifndef NDEBUG
        if (inputIdxs.size() != hashs.size())
            throw std::runtime_error("" LOCATION);
#endif

        insert(inputIdxs.size(), inputIdxs.data(), hashs.data());
    }

    void CuckooHasher::insert(
        const u64& sizeMaster,
        const u64* inputIdxsMaster,
        const block* hashsMaster)
    {
        std::array<u64, BATCH_SIZE> curHashIdxs, curAddrs, oldVals, inputIdxs;

        for (u64 step = 0; step < (sizeMaster + BATCH_SIZE - 1) / BATCH_SIZE; ++step)
        {
            u64 width = mParams.mNumHashes;
            u64 size = std::min<u64>(sizeMaster - step * BATCH_SIZE, BATCH_SIZE);
            u64 remaining = size;
            u64 tryCount = 0;

            //auto inputIdxs = inputIdxsMaster + BATCH_SIZE * step;
            auto hashs = hashsMaster + BATCH_SIZE * step;

            for (u64 i = 0; i < size; ++i)
            {

                inputIdxs[i] = inputIdxsMaster[BATCH_SIZE * step + i];
#ifndef NDEBUG
                if (neq(mHashes[inputIdxs[i]], AllOneBlock))
                {
                    std::cout << IoStream::lock << "cuckoo index " << inputIdxs[i] << " already inserted" << std::endl << IoStream::unlock;
                    throw std::runtime_error(LOCATION);
                }
#endif // ! NDEBUG

                mHashes[inputIdxs[i]] = hashs[i];
                curHashIdxs[i] = 0;
            }


            while (remaining && tryCount++ < 100)
            {

                // this data fetch can be slow (after the first loop).
                // As such, lets do several fetches in parallel.
                for (u64 i = 0; i < remaining; ++i)
                {
                    //curAddrs[i] = mHashes[inputIdxs[i]][curHashIdxs[i]] % mBins.size();
                    curAddrs[i] = getHash(inputIdxs[i], curHashIdxs[i]);// (mHashes.data() + inputIdxs[i] * width)[curHashIdxs[i]] % mBins.size();
                }

                // same thing here, this fetch is slow. Do them in parallel.
                for (u64 i = 0; i < remaining; ++i)
                {
                    u64 newVal = inputIdxs[i] | (curHashIdxs[i] << 56);
#ifdef THREAD_SAFE_CUCKOO
                    oldVals[i] = mBins[curAddrs[i]].mVal.exchange(newVal, std::memory_order_relaxed);
#else
                    oldVals[i] = mBins[curAddrs[i]].mVal;
                    mBins[curAddrs[i]].mVal = newVal;
#endif
            }
                // this loop will update the items that were just evicted. The main
                // idea of that our array looks like
                //     |XW__Y____Z __|
                // For X and W, which failed to be placed, lets write over them
                // with the vaues that they evicted.
                u64 putIdx = 0, getIdx = 0;
                while (putIdx < remaining && oldVals[putIdx] != u64(-1))
                {
                    inputIdxs[putIdx] = oldVals[putIdx] & (u64(-1) >> 8);
                    curHashIdxs[putIdx] = (1 + (oldVals[putIdx] >> 56)) % mParams.mNumHashes;
                    ++putIdx;
                }

                getIdx = putIdx + 1;

                // Now we want an array that looks like
                //  |ABCD___________| but currently have
                //  |AB__Y_____Z____| so lets move them
                // forward and replace Y, Z with the values
                // they evicted.
                while (getIdx < remaining)
                {
                    while (getIdx < remaining &&
                        oldVals[getIdx] == u64(-1))
                        ++getIdx;

                    if (getIdx >= remaining) break;

                    inputIdxs[putIdx] = oldVals[getIdx] & (u64(-1) >> 8);
                    curHashIdxs[putIdx] = (1 + (oldVals[getIdx] >> 56)) % mParams.mNumHashes;

                    // not needed. debug only
                    std::swap(oldVals[putIdx], oldVals[getIdx]);

                    ++putIdx;
                    ++getIdx;
                }

                remaining = putIdx;
        }

            // put any that remain in the stash.
            for (u64 i = 0, j = 0; i < remaining; ++j)
            {
                if (j >= mStash.size())
                    throw std::runtime_error(LOCATION);

                mStash[j].swap(inputIdxs[i], curHashIdxs[i]);

                if (inputIdxs[i] == u64(-1))
                    ++i;
            }
        }

    }

    u64 CuckooHasher::getHash(const u64& inputIdx, const u64& hashIdx)
    {
        return getHash(mHashes[inputIdx], hashIdx);
    }

    u64 CuckooHasher::getHash(const block& hash, const u64& hashIdx)
    {
        // use the hash index as the byte offset into the block, then cast as u64 and return.
        return *(u64*)(((u8*)&hash) + hashIdx) % mBins.size();
    }
//
//    void CuckooHasher::insertHelper(const u64& inputIdx, const u64& hashIdx, u64 numTries)
//    {
//        //++mTotalTries;
//
//        u64 xrHashVal = getHash(inputIdx, hashIdx);//mHashes[inputIdx][hashIdx];
//
//        auto addr = (xrHashVal) % mBins.size();
//
//        // replaces whatever was in this bin with our new item
//        //mBins[addr].swap(inputIdx, hashIdx);
//        {
//
//            u64 newVal = inputIdx | (hashIdx << 56);
//#ifdef THREAD_SAFE_CUCKOO
//            u64 oldVal = mBins[addr].mVal.exchange(newVal, std::memory_order_relaxed);
//#else
//            u64 oldVal = mBins[addr].mVal;
//            mBins[addr].mVal = newVal;
//#endif
//
//            if (oldVal == u64(-1))
//            {
//                inputIdx = u64(-1);
//            }
//            else
//            {
//                inputIdx = oldVal & (u64(-1) >> 8);
//                hashIdx = oldVal >> 56;
//            }
//        }
//
//        if (inputIdx != u64(-1))
//        {
//
//            // if idxItem is anything but -1, then we just exicted something.
//            if (numTries < 100)
//            {
//                // lets try to insert it into its next location
//                insertHelper(inputIdx, (hashIdx + 1) % mParams.mNumHashes, numTries + 1);
//            }
//            else
//            {
//                // put in stash
//                for (u64 i = 0; inputIdx != u64(-1); ++i)
//                {
//                    if (i >= mStash.size()) 
//                        throw std::runtime_error(LOCATION);
//                    mStash[i].swap(inputIdx, hashIdx);
//                }
//
//            }
//        }
//
//    }
//


    u64 CuckooHasher::find(const block& hashes)
    {
        if (mParams.mNumHashes == 2)
        {
            std::array<u64, 2>  addr{
                getHash(hashes, 0),
                getHash(hashes, 1) };

#ifdef THREAD_SAFE_CUCKOO
            std::array<u64, 2> val{
                mBins[addr[0]].mVal.load(std::memory_order::memory_order_relaxed),
                mBins[addr[1]].mVal.load(std::memory_order::memory_order_relaxed) };
#else
            std::array<u64, 2> val{
                mBins[addr[0]].mVal,
                mBins[addr[1]].mVal };
#endif

            if (val[0] != u64(-1))
            {
                u64 itemIdx = val[0] & (u64(-1) >> 8);

                bool match = eq(mHashes[itemIdx], hashes);

                if (match) return itemIdx;
            }

            if (val[1] != u64(-1))
            {
                u64 itemIdx = val[1] & (u64(-1) >> 8);

                bool match = eq(mHashes[itemIdx], hashes);

                if (match) return itemIdx;
            }


            // stash

            u64 i = 0;
            while (i < mStash.size() && mStash[i].isEmpty() == false)
            {
#ifdef THREAD_SAFE_CUCKOO
                u64 val = mStash[i].mVal.load(std::memory_order::memory_order_relaxed);
#else
                u64 val = mStash[i].mVal;
#endif
                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = eq(mHashes[itemIdx], hashes);

                    if (match)
                    {
                        return itemIdx;
                    }
                }

                ++i;
        }

    }
        else
        {

            for (u64 i = 0; i < mParams.mNumHashes; ++i)
            {
                u64 xrHashVal = getHash(hashes, i);
                auto addr = (xrHashVal) % mBins.size();


#ifdef THREAD_SAFE_CUCKOO
                u64 val = mBins[addr].mVal.load(std::memory_order::memory_order_relaxed);
#else
                u64 val = mBins[addr].mVal;
#endif

                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = eq(mHashes[itemIdx], hashes);

                    if (match)
                    {
                        return itemIdx;
                    }
                }
            }

            u64 i = 0;
            while (i < mStash.size() && mStash[i].isEmpty() == false)
            {
#ifdef THREAD_SAFE_CUCKOO
                u64 val = mStash[i].mVal.load(std::memory_order::memory_order_relaxed);
#else
                u64 val = mStash[i].mVal;
#endif

                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = eq(mHashes[itemIdx], hashes);

                    if (match)
                    {
                        return itemIdx;
                    }
                }

                ++i;
        }
        }

        return u64(-1);
    }


    void CuckooHasher::find(
        ArrayView<block> hashes,
        ArrayView<u64> idxs)
    {
#ifndef NDEBUG
        if (hashes.size() != idxs.size())
            throw std::runtime_error(LOCATION);
#endif

        find(hashes.size(), hashes.data(), idxs.data());
    }

    void CuckooHasher::find(const u64& numItemsMaster, const block * hashesMaster, const u64 * idxsMaster)
    {
        std::array<std::array<u64, 2>, BATCH_SIZE> findVal;
        std::array<u64, BATCH_SIZE> idxs;
        //std::array<block, BATCH_SIZE> idxs;


        for (u64 step = 0; step < (numItemsMaster + findVal.size() - 1) / findVal.size(); ++step)
        {
            auto numItems = std::min<u64>(numItemsMaster - findVal.size() * step, findVal.size());

            //auto idxs = idxsMaster + step * findVal.size();
            memcpy(idxs.data(), idxsMaster + step * findVal.size(), sizeof(u64) * BATCH_SIZE);
            auto hashes = hashesMaster + step * findVal.size();

            if (mParams.mNumHashes == 2)
            {
                std::array<u64, 2>  addr;

                for (u64 i = 0; i < numItems; ++i)
                {
                    idxs[i] = -1;

                    addr[0] = getHash(hashes[i], 0);
                    addr[1] = getHash(hashes[i], 1);

#ifdef THREAD_SAFE_CUCKOO
                    findVal[i][0] = mBins[addr[0]].mVal.load(std::memory_order::memory_order_relaxed);
                    findVal[i][1] = mBins[addr[1]].mVal.load(std::memory_order::memory_order_relaxed);
#else
                    findVal[i][0] = mBins[addr[0]].mVal;
                    findVal[i][1] = mBins[addr[1]].mVal;
#endif
                }

                for (u64 i = 0; i < numItems; ++i)
                {
                    if (findVal[i][0] != u64(-1))
                    {
                        u64 itemIdx = findVal[i][0] & (u64(-1) >> 8);
                        bool match = eq(mHashes[itemIdx], hashes[i]);
                        if (match) idxs[i] = itemIdx;
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
#ifdef THREAD_SAFE_CUCKOO
                    u64 val = mStash[i].mVal.load(std::memory_order::memory_order_relaxed);
#else
                    u64 val = mStash[i].mVal;
#endif
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





    bool CuckooHasher::Bin::isEmpty() const
    {
        return mVal == u64(-1);
    }

    u64 CuckooHasher::Bin::idx() const
    {
        return mVal  & (u64(-1) >> 8);
    }

    u64 CuckooHasher::Bin::hashIdx() const
    {
        return mVal >> 56;
    }

    void CuckooHasher::Bin::swap(u64 & idx, u64 & hashIdx)
    {
        u64 newVal = idx | (hashIdx << 56);
#ifdef THREAD_SAFE_CUCKOO
        u64 oldVal = mVal.exchange(newVal, std::memory_order_relaxed);
#else
        u64 oldVal = mVal;
        mVal = newVal;
#endif
        if (oldVal == u64(-1))
        {
            idx = hashIdx = u64(-1);
        }
        else
        {
            idx = oldVal & (u64(-1) >> 8);
            hashIdx = oldVal >> 56;
        }
    }
}
