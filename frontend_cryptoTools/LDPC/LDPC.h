#pragma once
#include <vector>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Matrix.h"
#include <unordered_set>
namespace osuCrypto
{
    class LDPC;



    struct diff
    {
        using T = Matrix<u64>;
        u64 mNumCols;
        T& mL, & mR;
        std::vector<std::array<u64, 3>> mBlocks;
        std::vector<u64>* mWeights;
        diff(T& l, T& r, std::vector<std::array<u64, 3>>& blocks, u64 numCols, std::vector<u64>* weights = nullptr)
            : mNumCols(numCols),
            mL(l), mR(r), mBlocks(blocks)
            , mWeights(weights)
        {}

    };


    class LDPC
    {
    public:

        //using diff = diff<LDPC2>;

        u64 mNumCols;
        Matrix<u64> mRows;
        std::vector<u64> mColStartIdxs, mColData;


        span<u64> col(u64 i)
        {
            auto b = mColStartIdxs[i];
            auto e = mColStartIdxs[i + 1];

            return span<u64>(mColData.data() + b, e - b);
        }


        LDPC() = default;
        LDPC(u64 cols, MatrixView<u64> points) { insert(cols, points); }

        void insert(u64 cols, MatrixView<u64> points);

        u64 cols() const { return mNumCols; }
        u64 rows() const { return mRows.rows(); }



        void blockTriangulate(
            std::vector<std::array<u64, 3>>& blocks,
            std::vector<u64>& rowPerm,
            std::vector<u64>& colPerm,
            bool verbose = false,
            bool stats = false,
            bool apply = true);

        u64 rowWeight()
        {
            return mRows.cols();
        }

        void validate();

    };

    //using diff = LDPC::diff;
    void print(std::ostream& o, const Matrix<u64>& rows, u64 cols);
    std::ostream& operator<<(std::ostream& o, const LDPC& s);
    std::ostream& operator<<(std::ostream& o, const diff& s);


}