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

        // The size of an row/column index
        using size_type = Size;

        // A row which contains indices of the non-zero columns.
        using Row = std::array<size_type, weight>;

        // A refernce to the full collection of rows.
        using RowSpan = span<Row>;

        // A owning collection of rows.
        using RowVector = std::vector<Row>;

        // The number of columns .
        size_type mNumCols;

        // The Rows which this LDPC operations on.
        RowSpan mRows;

        // The memory which holds mColStartIdxs and some padding...
        std::vector<size_type> mBackingColStartIdxs;

        // The columns of the matrix, each column is a list of
        // indices of the non-zero rows. The begining and then 
        // end of eah column is indexed by mColStartIdxs.
        std::vector<size_type> mColData;

        // The index of where each column starts inside mColData.
        span<size_type> mColStartIdxs;

        // Returns the i'th column which consits of the indicies 
        // of the non-zero rows.
        inline span<size_type> col(size_type i)
        {
            auto b = mColStartIdxs[i];
            auto e = mColStartIdxs[i + 1];

            return span<size_type>(mColData.data() + b, e - b);
        }


        LDPC() = default;
        LDPC(size_type cols, MatrixView<size_type> points) { insert(cols, points); }

        // Initialize this LDPC with the provided points.
        // points should be a conists with 'n' rows, each 
        // with 'weight' values. Each value should index
        // the non-zero column of the actual Matrix.
        void insert(size_type numColumns, MatrixView<size_type> points);

        // Returns the total number of columns.
        size_type cols() const { return mNumCols; }

        // Returns the total number of rows.
        size_type rows() const { return mRows.size(); }


        // Performs the block trianglization of the matrix
        // specifed by the insert(...) function.
        // @blocks: An output parameter which specify the blocks.
        //    Each value of blocks specifies {rowIdx, colIdx, width}
        //    where rowIdx, colIdx speficies where the block ends and
        //    width is the number of non-triagular rows at the end.
        // @rowPerm: An out parameter that defines how the rows should be permutated.
        // @colPerm: An out parameter that defines how the cols should be permutated.
        void blockTriangulate(
            std::vector<std::array<size_type, 3>>& blocks,
            std::vector<size_type>& rowPerm,
            std::vector<size_type>& colPerm,
            bool verbose = false,
            bool stats = false,
            bool apply = true);



        struct Idx
        {
            // The index of this row/column in the View
            size_type mViewIdx;

            // The index of this row/column in the input matrix.
            size_type mSrcIdx;

            //bool operator==(Idx const& y) const
            //{
            //    if (mViewIdx == y.mViewIdx)
            //        assert(mSrcIdx == y.mSrcIdx);
            //    else
            //        assert(mSrcIdx != y.mSrcIdx);
            //    return mViewIdx == y.mViewIdx;
            //}
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


        //struct RowIter
        //{
        //    View& mH;
        //    gsl::span<size_type, weight> mRow;
        //    size_type mPos;
        //
        //    RowIter(View& H, const Idx& i, size_type p);
        //
        //    void operator++();
        //    Idx operator*();
        //};
        //
        //struct ColIter
        //{
        //    View& mH;
        //    span<size_type> mCol;
        //    size_type mPos;
        //    ColIter(View& H, const Idx& i, size_type p);
        //    void operator++();
        //    Idx operator*();
        //    size_type srcIdx();
        //    operator bool();
        //};

        // The Data structure used to maintain the State of the 
        // blockTriangulate algorithm.
        struct View
        {
            // The data that prepresents the state of each row.
            std::vector<RowData> mRowData;

            // The index of special dummy/empty RowData which
            // is at the end of mRowData. This is only here as a 
            // performance optimization.
            std::array<size_type, weight + 1> mWeightSetSentinals;

            gsl::span<RowData, weight + 1> mWeightSets;

            // A list of linked-lists each the i'th linked-list
            // contains all rows with weight i. Each list is specified 
            // by an index into mRowData. The next and prev nodes are
            // specified in the RowData struct.
            //std::array<size_type, weight + 1> mWeightSetBegins;

            //std::array<size_type, weight + 1> mWeightSetEnds;

            // The size of the mWeightSets linked-lists.
            std::array<size_type, weight + 1> mWeightSetSizes;

            // A map which maps a column index in the View to the 
            // column that it corresponds to in the input matrix.
            std::vector<size_type> mColNOMap;

            // A map which maps a column index in the input matrix
            //  to the column that it corresponds to in the View.
            std::vector<size_type> mColONMap;

            // A pointer to the LDPC which this View is for.
            LDPC* mH;



            inline size_type& weightSetFront(size_type i)
            {
                return mWeightSets[i].mNextWeightNode;
            }

            inline size_type& weightSetBack(size_type i)
            {
                return mWeightSets[i].mPrevWeightNode;
            }

            inline size_type& weightSetEnd(size_type i)
            {
                return mWeightSetSentinals[i];
            }

            inline bool weightSetHasRows(size_type i)
            {
                return weightSetEnd(i) != weightSetFront(i);
            }

            inline size_type& weightSetSize(size_type i)
            {
                return mWeightSetSizes[i];
            }

            inline void weightSetPopFront(size_type i)
            {
#ifdef LDPC_STATS
                assert(mWeightSetSizes[i]);
                --mWeightSetSizes[i];
#endif
                auto& front = mRowData[weightSetFront(i)];
                auto nextIdx = front.mNextWeightNode;

                mWeightSets[i].mNextWeightNode = nextIdx;

                if (nextIdx == weightSetEnd(i))
                    mWeightSets[i].mPrevWeightNode = weightSetEnd(i);
            }

            inline void weightSetPushBack(size_type i, size_type rowIdx)
            {
#ifdef LDPC_STATS
                ++mWeightSetSizes[i];
#endif

                auto oldBackIdx = mWeightSets[i].mPrevWeightNode;
                auto& row = mRowData[rowIdx];
                mWeightSets[i].mPrevWeightNode = rowIdx;
                row.mNextWeightNode = weightSetEnd(i);
                mWeightSets[i].mNextWeightNode = rowIdx;
                row.mPrevWeightNode = weightSetEnd(i);

                //if (oldBackIdx == weightSetEnd(i))
                //{
                //}
                //else
                //{
                //    mRowData[oldBackIdx].mNextWeightNode = rowIdx;
                //    row.mPrevWeightNode = oldBackIdx;
                //}
            }

            // Initialize the data structures.
            void init(LDPC& b);

            // Swaps the provided rows in the View. Also
            // updates the inputs so that they still correspond 
            // the the same logical rows.
            void swapRows(Idx& r0, Idx& r1);

            // Swaps the provided rows in the View. 
            void swapCol(Idx& c0, Idx& c1);;

            //size_type rowWeight(size_type r)
            //{
            //    return mRowData[mRowData[r].mNOMap].mWeight;
            //}

            // Returns the Idx for the given view row index.
            Idx rowIdx(size_type viewIdx)
            {
                return { viewIdx, mRowData[viewIdx].mNOMap };
            }

            // Returns the Idx for the given input row index.
            Idx rowSrcIdx(size_type viewIdx)
            {
                return { mRowData[viewIdx].mONMap, viewIdx };
            }

            // Returns the Idx for the given view column index.
            Idx colIdx(size_type viewIdx)
            {
                return { viewIdx, mColNOMap[viewIdx] };
            }

            //RowIter rowIterator(const Idx& row)
            //{
            //    assert(row.mSrcIdx == rowIdx(row.mViewIdx).mSrcIdx);

            //    return RowIter(*this, row, 0);
            //}

            //ColIter colIterator(const Idx& col)
            //{
            //    assert(col.mSrcIdx == colIdx(col.mViewIdx).mSrcIdx);
            //    return ColIter(*this, col, 0);
            //}

            // returns the Row with min weight and sets its 
            // weight to zero. The returned row is specified 
            // by the out parameter u and its weight wi.
            void popMinWeightRow(Idx& u, size_type& wi);

            // Decrements the weight of the specifed row by 1.
            void decRowWeight(size_type idx);


            // Decrements the weight of the specifed row by 1.
            void incRowWeight(size_type idx);

            void shuffleWeights(PRNG& prng);

            // Returns the current matrix with the view/permutation 
            // applied to it.
            RowVector applyPerm()const;

            // Apply the current View/permutations to the provided rows.
            void applyPerm(RowSpan rows) const;

        };

        View mView;

    };


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
            o << "   " << i << "\n";
        }
        for (u64 i = 0; i < cols; ++i)
        {
            o << (i % 10) << " ";
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