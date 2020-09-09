#pragma once
#include <vector>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Matrix.h"
#include "C:\libs\eigen\Eigen\SparseCore"
#include <unordered_set>
namespace osuCrypto
{
    void cuckoo(CLP& cmd);



    class LDPC
    {
    public:
        struct diff
        {
            LDPC& mL, & mR;
            std::vector<u64> mRIdx, mCIdx;
            diff(LDPC& l, LDPC& r, std::vector<u64> rIdx, std::vector<u64> cIdx)
                :mL(l), mR(r), mRIdx(rIdx), mCIdx(cIdx)
            {}

        };


        u64 mNumCols;
        class Column;
        Matrix<u64> mRows;
        std::vector<u64> mColStartIdxs, mColData;
        //std::vector<u64> mRowSrcIdx, mColSrcIdx;
        

        span<u64> col(u64 i)
        {
            auto b = mColStartIdxs[i];
            auto e = mColStartIdxs[i+1];

            return span<u64>(mColData.data() + b, e - b);
        }

        //class Column
        //{
        //public:
        //    u64 mIdx;
        //    std::vector<u64> mRowIdxs;
        //};

        //std::vector<Column> mCols;
        LDPC() = default;
        LDPC(u64 rows, u64 cols, u64 rowWeight, std::vector<std::array<u64, 2>>& points) { insert(rows, cols, rowWeight, points); }

        void insert(u64 rows, u64 cols, u64 rowWeight, std::vector<std::array<u64, 2>>& points);

        void moveRows(u64 destIter, std::unordered_set<u64> srcRows);

        void swapRow(u64 r0, u64 r1);

        void moveCols(u64 destIter, std::unordered_set<u64> srcCols);

        void swapCol(u64 c0, u64 c1);

        u64 cols() const { return mNumCols; }
        u64 rows() const { return mRows.rows(); }

        // returns the hamming weight of row r where only the columns
        // indexed by { cBegin, ..., cols()-1 } are considered.
        u64 HamV(u64 r, u64 cBegin)
        {
            u64 h = 0;
            for (u64 i = 0; i < mRows.cols(); ++i)
            {
                auto col = mRows(r, i);
                h += (col >= cBegin);
            }
            return h;
        }


        void blockTriangulate(
            std::vector<u64>& R,
            std::vector<u64>& C,
            bool verbose);


        void blockTriangulate2(
            std::vector<u64>& R,
            std::vector<u64>& C,
            bool verbose,
            bool stats);



        void partition(
            const std::vector<u64>& R,
            const std::vector<u64>& C,
            bool v);



        LDPC applyPerm(
            std::vector<u64>& R,
            std::vector<u64>& C);


        u64 rowWeight()
        {
            return mRows.cols();
        }

    };

    std::ostream& operator<<(std::ostream& o, const LDPC& s);
        
}