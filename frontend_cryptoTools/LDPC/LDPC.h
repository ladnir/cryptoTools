#pragma once
#include <vector>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/Matrix.h"
#include <unordered_set>
#include <cassert>

#define LDPC_STATS
#define LDPC_VERBOSE
#define LDPC_DEBUG

namespace osuCrypto
{



    struct Diff
    {
        using T = Matrix<u64>;
        u64 mNumCols;
        T mL, mR;
        std::vector<std::array<u64, 3>> mBlocks;
        std::vector<u64> mWeights;
        std::vector<std::string> mData2;

        Diff(T& l, T& r, std::vector<std::array<u64, 3>>& blocks, u64 numCols, std::vector<u64>* weights = nullptr, std::vector<std::string>* data2 = nullptr)
            : mNumCols(numCols),
            mL(l), mR(r), mBlocks(blocks)
        {
        
            if (weights)
                mWeights = (*weights);

            if (data2)
                mData2 = (*data2);
        }

    };

    template<typename MatrixType, typename Size>
    Diff diff(const MatrixType& l, const MatrixType& r, std::vector<std::array<Size, 3>>& b, Size numCols, std::vector<Size>* w = nullptr, std::vector<std::string>* data2 = nullptr)
    {
        Matrix<u64> L(l.size(), l[0].size()), R(r.size(), r[0].size());

        for (u64 i = 0; i < L.rows(); ++i)
            for (u64 j = 0; j < L.cols(); ++j)
                L[i][j] = l[i][j];
        for (u64 i = 0; i < R.rows(); ++i)
            for (u64 j = 0; j < R.cols(); ++j)
                R[i][j] = r[i][j];


        std::vector<u64> weights;
        std::vector<std::array<u64, 3>> blocks(b.size());
        for (u64 i = 0; i < b.size(); ++i)
            for(u64 j = 0; j < b[i].size(); ++j)
                blocks[i][j] = b[i][j];

        if (w)
        {
            weights.resize(w->size());
            for (u64 i = 0; i < weights.size(); ++i)
            {
                weights[i] = (*w)[i];
            }
        }

        return Diff(L, R, blocks, numCols, &weights, data2);        
    }

    template<typename Size, int weight>
    class LDPC
    {
    public:

        using size_type = Size;
        using Row = std::array<size_type, weight>;
        using RowSpan = span<Row>;
        using RowVector = std::vector<Row>;

        size_type mNumCols;

        //MatrixView<size_type> mRows;
        RowSpan mRows;
        std::vector<size_type> mBackingColStartIdxs, mColData;
        span<size_type> mColStartIdxs;
        span<size_type> col(size_type i)
        {
            auto b = mColStartIdxs[i];
            auto e = mColStartIdxs[i + 1];

            return span<size_type>(mColData.data() + b, e - b);
        }


        LDPC() = default;
        LDPC(size_type cols, MatrixView<size_type> points) { insert(cols, points); }

        void insert(size_type cols, MatrixView<size_type> points);

        size_type cols() const { return mNumCols; }
        size_type rows() const { return mRows.size(); }



        void blockTriangulate(
            std::vector<std::array<size_type, 3>>& blocks,
            std::vector<size_type>& rowPerm,
            std::vector<size_type>& colPerm,
            bool verbose = false,
            bool stats = false,
            bool apply = true);

        size_type rowWeight()
        {
            return weight;
        }

        void validate();


        struct Idx
        {
            size_type mViewIdx, mSrcIdx;

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
            size_type mONMap;

            // The current row at this position has as input index of.
            size_type mNOMap;

            // The current of this row.
            size_type mWeight;

            // The previous row with the same weight.
            size_type mPrevWeightNode;

            // the next row with the same weight
            size_type mNextWeightNode;
        };

        struct View;


        struct RowIter
        {
            View& mH;
            gsl::span<size_type, weight> mRow;
            size_type mPos;

            RowIter(View& H, const Idx& i, size_type p);

            void operator++();
            Idx operator*();
        };

        struct ColIter
        {
            View& mH;
            span<size_type> mCol;
            size_type mPos;

            ColIter(View& H, const Idx& i, size_type p);
            void operator++();
            Idx operator*();
            size_type srcIdx();
            operator bool();
        };

        struct View
        {



            size_type mNullRow;
            std::vector<RowData> mRowData;
            std::array<size_type, weight + 1> mWeightSets;
            std::array<size_type, weight + 1> mWeightSetSizes;

            std::vector<size_type> mColNOMap, mColONMap;
            LDPC* mH;
            //MatrixView<u64> mRows;


            void init(LDPC& b);

            void swapRows(Idx& r0, Idx& r1);

            void swapCol(Idx& c0, Idx& c1);;

            size_type rowWeight(size_type r)
            {
                return mRowData[mRowData[r].mNOMap].mWeight;
            }

            Idx rowIdx(size_type viewIdx)
            {
                return { viewIdx, mRowData[viewIdx].mNOMap };
            }
            Idx rowSrcIdx(size_type viewIdx)
            {
                return { mRowData[viewIdx].mONMap, viewIdx };
            }
            Idx colIdx(size_type viewIdx)
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

            std::pair<Idx, size_type> popMinWeightRow();

            void decRowWeight(const Idx& idx);

            RowVector applyPerm()const;
            void applyPerm(RowSpan rows) const;

        };

        View mView;

    };

    //using diff = LDPC::diff;

    template<typename Size>
    void print(std::ostream& o, const MatrixView<Size>& rows, u64 cols)
    {

        for (u64 i = 0; i < rows.rows(); ++i)
        {
            std::unordered_set<u64> c;
            for (u64 j = 0; j < rows.cols(); j++)
                c.insert(rows(i, j));

            for (u64 j = 0; j < cols; ++j)
            {
                if (c.find(j) != c.end())
                {
                    o << "1 ";
                }
                else
                {
                    o << ". ";
                }
            }
            o << "\n";
        }

        o << "\n";
    }
    


    template<typename Size, int weight>
    std::ostream& operator<<(std::ostream& o, const LDPC<Size, weight>& s)
    {
        MatrixView<Size> rows((Size*)s.mRows.data(), s.mRows.size(), weight);

        print(o, rows, s.cols());
        return o;
    }

    std::ostream& operator<<(std::ostream& o, const Diff& s);

    template<typename Size, int weight>
    MatrixView<Size> view(typename LDPC<Size, weight>::RowSpan mtx)
    {
        return MatrixView<Size>((Size*)mtx.data(), mtx.size(), weight);
    }

}