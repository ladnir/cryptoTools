#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include <atomic>

namespace osuCrypto
{

	// The parameters that define a cuckoo table.
    struct CuckooParam
    {
        u64 mStashSize;
        double mBinScaler;
        u64 mNumHashes, mN;

        u64 numBins() { return static_cast<u64>(mN * mBinScaler); }
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

   // Two variants of the Cuckoo implementation.
   enum CuckooTypes
   {
	   ThreadSafe,
	   NotThreadSafe
   };

   // Two variants of the Cuckoo values.
   template<CuckooTypes M> struct CuckooStorage;

   // Thread safe version requires atomic u64
   template<> struct CuckooStorage<ThreadSafe> { std::atomic<u64> mVal; };

   // Not Thread safe version only requires u64.
   template<> struct CuckooStorage<NotThreadSafe> { u64 mVal; };

   // A cuckoo hashing implementation. The cuckoo hash table takes {value, index}
   // pairs as input and stores the index. 
   template<CuckooTypes Mode = ThreadSafe>
   class CuckooIndex
    {

    public:
        CuckooIndex();
        ~CuckooIndex();

		// the maximum number of hash functions that are allowed.
		#define CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT 4

        struct Bin
        {
			CuckooStorage<Mode> mS;
			Bin() {
				mS.mVal = (-1);}
			Bin(u64 idx, u64 hashIdx) { mS.mVal = (idx | (hashIdx << 56)); }
			Bin(const Bin& b) { mS.mVal = (b.load()); }

			bool isEmpty() const { return  load() == u64(-1); }
			u64 idx() const { return  load()  & (u64(-1) >> 8); }
			u64 hashIdx() const { return  load() >> 56; }

			void swap(u64& idx, u64& hashIdx)
			{
				u64 newVal = idx | (hashIdx << 56);
				auto oldVal = exchange(newVal);
				idx = oldVal & (u64(-1) >> 8);
				hashIdx = (oldVal >> 56);
			}

			template<CuckooTypes M = Mode>
			typename std::enable_if< M == ThreadSafe, u64>::type exchange(u64 newVal) { return mS.mVal.exchange(newVal, std::memory_order_relaxed); }
			template<CuckooTypes M = Mode>
			typename std::enable_if< M == ThreadSafe, u64>::type load() const { return mS.mVal.load(std::memory_order_relaxed); }


			template<CuckooTypes M = Mode>
			typename std::enable_if< M == NotThreadSafe, u64>::type exchange(u64 newVal) { auto v = mS.mVal; mS.mVal = newVal;  return v; }
			template<CuckooTypes M = Mode>
			typename std::enable_if< M == NotThreadSafe, u64>::type load() const { return mS.mVal; }

        };


        void print() const;


        void init(const u64& n, const u64& statSecParam, u64 stashSize, u64 h);
        void init(const CuckooParam& params);

		static CuckooParam selectParams(const u64& n, const u64& statSecParam, const u64& stashSize, const u64& h);

        void insert(span<block> items, block hashingSeed, u64 startIdx = 0);

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

		// checks that the cuckoo index is correct
		void validate(span<block> inputs, block hashingSeed);

		// Return the number of items in the stash.
		u64 stashUtilization() const;

        std::vector<block> mHashes;

        std::vector<Bin> mBins;
        std::vector<Bin> mStash;

		// The total number of (re)inserts that were required,
        u64 mTotalTries;

		// Compare two Index.
        bool operator==(const CuckooIndex& cmp)const;
        bool operator!=(const CuckooIndex& cmp)const;

        CuckooParam mParams;

        u64 getHash(const u64& inputIdx, const u64& hashIdx);

        static u64 getHash(const block& hash, const u64& hashIdx, u64 num_bins);
        static u8 minCollidingHashIdx(u64 target, block& hashes, u8 numHashFunctions, u64 numBins);
    };
}
