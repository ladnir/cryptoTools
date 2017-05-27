#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/ArrayView.h"
#include "cryptoTools/Common/Matrix.h"
//#include <mutex>
#include <atomic>

#define THREAD_SAFE_CUCKOO

namespace osuCrypto
{
    struct CuckooParam
    {
        u64 mStashSize;
        double mBinScaler;
        u64 mNumHashes, mN;

        u64 numBins() { return mN * mBinScaler; }
    };


   extern CuckooParam k2n32s40CuckooParam;
   extern CuckooParam k2n30s40CuckooParam;
   extern CuckooParam k2n28s40CuckooParam;
   extern CuckooParam k2n24s40CuckooParam;
   extern CuckooParam k2n20s40CuckooParam;
   extern CuckooParam k2n16s40CuckooParam;
   extern CuckooParam k2n12s40CuckooParam;
   extern CuckooParam k2n08s40CuckooParam;
   extern CuckooParam k2n07s40CuckooParam;
   extern CuckooParam k2n06s40CuckooParam;
   extern CuckooParam k2n05s40CuckooParam;
   extern CuckooParam k2n04s40CuckooParam;
   extern CuckooParam k2n03s40CuckooParam;
   extern CuckooParam k2n02s40CuckooParam;
   extern CuckooParam k2n01s40CuckooParam;


    class CuckooIndex
    {
    public:
        CuckooIndex();
        ~CuckooIndex();

        struct Bin
        {
            Bin() :mVal(-1) {}
            Bin(u64 idx, u64 hashIdx) : mVal(idx | (hashIdx << 56)) {}

            bool isEmpty() const;
            u64 idx() const;
            u64 hashIdx() const;

            void swap(u64& idx, u64& hashIdx);
#ifdef THREAD_SAFE_CUCKOO
            Bin(const Bin& b) : mVal(b.mVal.load(std::memory_order_relaxed)) {}
            Bin(Bin&& b) : mVal(b.mVal.load(std::memory_order_relaxed)) {}
            std::atomic<u64> mVal;
#else
            Bin(const Bin& b) : mVal(b.mVal) {}
            Bin(Bin&& b) : mVal(b.mVal) {}
            u64 mVal;
#endif
        };


        void print() const;


        void init(const u64& n, const u64& statSecParam, bool noStash = false);
        void init(const CuckooParam& params);

        static CuckooParam selectParams(const u64& n, const u64& statSecParam, bool noStash);

        void insert(span<block> items, block hashingSeed);

        // insert single index with pre hashed values with error checking
        void insert(const u64& IdxItem, const block& hashes);

        // insert several items with pre-hashed values with error checking
        void insert(span<u64> itemIdxs, span<block> hashs);

        // insert several items with pre-hashed values
        void insert(const u64& numInserts, const u64* itemIdxs, const block* hashs);

        // find a single item with pre-hashed values and error checking.
        u64 find(const block& hash);

        // find several items with pre hashed values, the indexes that are found are written to the idxs array.
        void find(span<block> hashes, span<u64> idxs);

        // find several items with pre hashed values, the indexes that are found are written to the idxs array.
        void find(const u64& numItems, const  block* hashes, const u64* idxs);


        std::vector<block> mHashes;

        std::vector<Bin> mBins;
        std::vector<Bin> mStash;


        u64 mTotalTries;

        bool operator==(const CuckooIndex& cmp)const;
        bool operator!=(const CuckooIndex& cmp)const;

        CuckooParam mParams;

        u64 getHash(const u64& inputIdx, const u64& hashIdx);

        static u64 getHash(const block& hash, const u64& hashIdx, u64 num_bins);
        static u8 minCollidingHashIdx(u64 target, block& hashes, u8 numHashFunctions, u64 numBins);
        //void insertHelper(u64 IdxItem, u64 hashIdx, u64 numTries);

    };

}
