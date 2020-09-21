#pragma once
#include <vector>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Matrix.h"
#include <unordered_set>
#include <cassert>

namespace osuCrypto
{
    class LDPC;



    struct diff
    {
        using T = MatrixView<u64>;
        u64 mNumCols;
        T& mL, & mR;
        std::vector<std::array<u64, 3>> mBlocks;
        std::vector<u64>* mWeights;
        std::vector<std::string>* mData2;
        diff(T l, T r, std::vector<std::array<u64, 3>>& blocks, u64 numCols, std::vector<u64>* weights = nullptr, std::vector<std::string>* data2 = nullptr)
            : mNumCols(numCols),
            mL(l), mR(r), mBlocks(blocks)
            , mWeights(weights), mData2(data2)
        {}

    };


    class LDPC
    {
    public:

        //using diff = diff<LDPC2>;

        u64 mNumCols;
        MatrixView<u64> mRows;
        //Matrix<u64> mRows;
        std::vector<u64> mBackingColStartIdxs, mColData;
        span<u64> mColStartIdxs;
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


        struct Idx
        {
            u64 mViewIdx, mSrcIdx;

            bool operator==(Idx const& y) const
            {
                if (mViewIdx == y.mViewIdx)
                {
                    assert(mSrcIdx == y.mSrcIdx);
                }
                else
                    assert(mSrcIdx != y.mSrcIdx);


                return mViewIdx == y.mViewIdx;
            }
        };


        struct RowData
        {
            // The input row at this position has been moved
            // to this new row index.
            u64 mONMap;

            // The current row at this position has as input index of.
            u64 mNOMap;

            // The current of this row.
            u64 mWeight;

            // The previous row with the same weight.
            RowData* mPrevWeightNode;

            // the next row with the same weight
            RowData* mNextWeightNode;
        };

        struct View;


        struct RowIter
        {
            View& mH;
            span<u64> mRow;
            u64 mPos;

            RowIter(View& H, const Idx& i, u64 p);

            void operator++();
            Idx operator*();
        };

        struct ColIter
        {
            View& mH;
            span<u64> mCol;
            u64 mPos;

            ColIter(View& H, const Idx& i, u64 p);
            void operator++();
            Idx operator*();
            u64 srcIdx();
            operator bool();
        };

        struct View
        {



            std::vector<RowData> mRowData;
            std::vector<RowData*> mWeightSets;

            std::vector<u64> mColNOMap, mColONMap;
            LDPC* mH;
            //MatrixView<u64> mRows;


            void init(LDPC& b);

            void swapRows(Idx& r0, Idx& r1);

            void swapCol(Idx& c0, Idx& c1);;

            u64 rowWeight(u64 r)
            {
                return mRowData[mRowData[r].mNOMap].mWeight;
            }

            Idx rowIdx(u64 viewIdx)
            {
                return { viewIdx, mRowData[viewIdx].mNOMap };
            }
            Idx rowSrcIdx(u64 viewIdx)
            {
                return { mRowData[viewIdx].mONMap, viewIdx };
            }
            Idx colIdx(u64 viewIdx)
            {
                return { viewIdx, mColNOMap[viewIdx] };
            }

            RowIter rowIterator(const Idx& row)
            {
                assert(row.mSrcIdx == rowIdx(row.mViewIdx).mSrcIdx);

                return RowIter(*this, row, 0);
            }

            ColIter colIterator(const Idx& col)
            {
                assert(col.mSrcIdx == colIdx(col.mViewIdx).mSrcIdx);
                return ColIter(*this, col, 0);
            }

            std::pair<Idx, u64> popMinWeightRow();

            void decRowWeight(const Idx& idx);

            Matrix<u64> applyPerm()const;
            void applyPerm(MatrixView<u64> rows) const;

        };

        View mView;

    };

    //using diff = LDPC::diff;
    void print(std::ostream& o, const MatrixView<u64>& rows, u64 cols);
    std::ostream& operator<<(std::ostream& o, const LDPC& s);
    std::ostream& operator<<(std::ostream& o, const diff& s);


}