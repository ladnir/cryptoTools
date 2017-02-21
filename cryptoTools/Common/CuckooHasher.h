#pragma once
#include <cryptoTools/Common/ArrayView.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/MatrixView.h>
#include <atomic>

using osuCrypto::u64;
using osuCrypto::ArrayView;
using osuCrypto::MatrixView;

namespace osuCrypto {

struct CuckooParam {
    double mBinScaler;
    u64 mNumHashes;
    u64 mSenderBinSize;
};

class CuckooHasher {
    public:
        CuckooHasher() = delete;
        CuckooHasher(size_t stash_size) : mTotalTries(0), mStashSize(stash_size) {}
        ~CuckooHasher();

        struct Bin {
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

        struct Workspace {
            Workspace(u64 n) : curAddrs(n), curHashIdxs(n), oldVals(n) {}
            std::vector<u64> curAddrs, curHashIdxs, oldVals;
            std::vector<std::array<u64, 2>> findVal;
        };

        u64 mTotalTries;

        bool operator==(const CuckooHasher& cmp)const;
        bool operator!=(const CuckooHasher& cmp)const;

        CuckooParam mParams;

        void print() const;
        void init(u64 n, u64 statSecParam);
        void insert(u64 IdxItem, ArrayView<u64> hashes);
        void insertHelper(u64 IdxItem, u64 hashIdx, u64 numTries);

        void insertBatch(ArrayView<u64> itemIdxs, MatrixView<u64> hashs, Workspace& workspace);

        u64 find(ArrayView<u64> hashes);
        u64 findBatch(MatrixView<u64> hashes, ArrayView<u64> idxs, Workspace& wordkspace);

        std::vector<u64> mHashes;
        MatrixView<u64> mHashesView;
        std::vector<Bin> mBins;
        std::vector<Bin> mStash;
        size_t mStashSize;
};

} // namespace osuCrypto
