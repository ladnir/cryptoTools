



#include "LDPC.h"

#ifndef LDPC_DEBUG
#define NDEBUG
#endif
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/TestCollection.h>
#include <random>
#include <numeric>
#include <sstream>
//#include "sparsehash/dense_hash_set"
//#include "sparsehash/sparse_hash_set"

//#include "../flat_hash_map/bytell_hash_map.hpp"
//#include "../hopscotch-map/include/tsl/bhopscotch_set.h"
//#include "../hopscotch-map/include/tsl/hopscotch_set.h"
//#include "../ordered-map/include/tsl/ordered_set.h"
//#include "../sparse-map/include/tsl/sparse_set.h"
//#include "../robin-map/include/tsl/robin_set.h"
//#include "../cpp-btree/btree/set.h"

#include "cryptoTools/Common/CuckooIndex.h"
#include <unordered_set>
//#include "absl/container/btree_set.h"
//#include "absl/container/flat_hash_set.h"
//#include "absl/container/node_hash_set.h"


//#define NULL_NODE Size(-1)

namespace osuCrypto
{


    struct ColorBuff
    {
        std::ostream& mO;
        oc::Color mCur = oc::Color::Default;
        std::stringstream mSS;

        ColorBuff(std::ostream& o)
            : mO(o)
        {}

        ~ColorBuff()
        {
            mO << mSS.str();
        }

        ColorBuff& operator<<(const oc::Color& t)
        {
            if (mCur != t)
            {
                mO << mSS.str() << t;
                mSS = std::stringstream{};
                mCur = t;
            }
            return *this;
        }


        template<typename T>
        ColorBuff& operator<<(const T& t)
        {
            mSS << t;
            return *this;
        }
    };

    //std::ostream& operator<<(std::ostream& o, const diff& s)
    //{
    //    std::array<oc::Color, 2> colors{ oc::Color::Blue, oc::Color::Green };
    //    u8 rowColorIdx = 0;
    //    for (u64 i = 0; i < s.mL.rows(); ++i)
    //    {

    //        std::unordered_set<u64> lc, rc;
    //        for (u64 j = 0; j < s.mL.cols(); j++)
    //            lc.insert(s.mL(i, j));
    //        for (u64 j = 0; j < s.mR.cols(); j++)
    //            rc.insert(s.mR(i, j));

    //        auto diffCols = lc;
    //        for (auto c : rc)
    //        {
    //            auto iter = diffCols.find(c);
    //            if (iter == diffCols.end())
    //                diffCols.insert(c);
    //            else
    //                diffCols.erase(iter);
    //        }

    //        //if (std::find(s.mRIdx.begin(), s.mRIdx.end(), i) != s.mRIdx.end())
    //        //{
    //        //    rowColorIdx ^= 1;
    //        //}

    //        auto colorIdx = rowColorIdx;
    //        for (u64 j = 0; j < s.mL.cols(); ++j)
    //        {

    //            //if (std::find(s.mCIdx.begin(), s.mCIdx.end(), j) != s.mCIdx.end())
    //            //{
    //            //    colorIdx ^= 1;
    //            //}


    //            if (diffCols.find(j) != diffCols.end())
    //                o << oc::Color::Red;
    //            else
    //                o << colors[colorIdx];

    //            if (lc.find(j) != lc.end())
    //            {
    //                o << "1 ";
    //            }
    //            else
    //            {
    //                o << "0 ";
    //            }
    //            o << oc::Color::Default;
    //        }

    //        if (s.mWeights)
    //            o << "   " << (*s.mWeights)[i];
    //        o << "\n";
    //    }

    //    return o;
    //}


    std::ostream& operator<<(std::ostream& o, const Diff& s)
    {
        std::array<oc::Color, 2> colors{ oc::Color::Blue, oc::Color::Red };

        //ColorBuff o(oo);
        u8 rowColorIdx = 0;
        std::stringstream ss;
        for (u64 i = 0; i < s.mL.rows(); ++i)
        {

            std::unordered_set<u64> lc, rc;
            for (u64 j = 0; j < s.mL.cols(); j++)
                lc.insert(s.mL(i, j));
            for (u64 j = 0; j < s.mR.cols(); j++)
                rc.insert(s.mR(i, j));

            auto diffCols = lc;
            for (auto c : rc)
            {
                auto iter = diffCols.find(c);
                if (iter == diffCols.end())
                    diffCols.insert(c);
                else
                    diffCols.erase(iter);
            }

            for (u64 k = 0; k < s.mBlocks.size(); ++k)
            {
                if (s.mBlocks[k][0] == i)
                {
                    rowColorIdx ^= 1;
                    break;
                }
            }
            auto colorIdx = rowColorIdx;
            for (u64 j = 0; j < s.mNumCols; ++j)
            {
                for (u64 k = 0; k < s.mBlocks.size(); ++k)
                {
                    if (s.mBlocks[k][1] == j)
                    {
                        colorIdx ^= 1;
                        break;
                    }
                }

                if (diffCols.find(j) != diffCols.end())
                    o << ss.str() << oc::Color::Green;
                else
                    o << ss.str() << oc::Color::Default;

                if (lc.find(j) != lc.end())
                {
                    o << "1 ";
                }
                else
                {
                    o << (colorIdx ? ". " : "  ");
                }
                o << oc::Color::Default;
            }

            if (s.mWeights.size())
                o << "   " << s.mWeights[i];


            if (s.mData2.size())
                o << "   " << s.mData2[i];
            o << "\n";
        }

        for (u64 i = 0; i < s.mNumCols; ++i)
        {
            o << (i % 10) << " ";
        }
        o << '\n';
        return o;
    }

    template<typename Size, int weight>
    void LDPC<Size, weight>::View::init(LDPC<Size, weight>& b)
    {
        //mH(b)
        mH = &b;
        mRowData.resize(b.rows() + 1);
        mNullRow = b.rows();

        //mWeightSets.resize(0);
        //mWeightSets.resize(b.rowWeight() + 1, mNullRow);
        std::fill(mWeightSets.begin(), mWeightSets.end(), mNullRow);


        mColNOMap.resize(b.cols());
        mColONMap.resize(b.cols());

        auto nn = mRowData.size();
        auto row = mRowData.data();
        for (u64 i = 0; i < nn; ++i)
        {
            row[0].mNOMap = i;
            row[0].mONMap = i;
            row[0].mPrevWeightNode = i - 1;
            row[0].mNextWeightNode = i + 1;
            row[0].mWeight = weight;
            ++row;
        }
        assert(row == mRowData.data() + mRowData.size());


        mRowData.front().mPrevWeightNode = mNullRow;
        mRowData.back().mNextWeightNode = mNullRow;
        mWeightSets.back() = 0;

#ifdef LDPC_STATS
        mWeightSetSizes.back() = b.rows();
        std::fill(mWeightSetSizes.begin(), mWeightSetSizes.end(), 0);
#endif

        for (u64 i = 0; i < mColNOMap.size(); ++i)
            mColNOMap[i] = mColONMap[i] = i;
    }

    template<typename Size, int weight>
    void LDPC<Size, weight>::View::swapRows(Idx& r0, Idx& r1)
    {
#ifdef LDPC_DEBUG
        assert(r0.mSrcIdx == rowIdx(r0.mViewIdx).mSrcIdx);
        assert(r1.mSrcIdx == rowIdx(r1.mViewIdx).mSrcIdx);
#endif

        std::swap(mRowData[r0.mViewIdx].mNOMap, mRowData[r1.mViewIdx].mNOMap);
        std::swap(mRowData[r0.mSrcIdx].mONMap, mRowData[r1.mSrcIdx].mONMap);
        std::swap(r0.mSrcIdx, r1.mSrcIdx);
    }

    template<typename Size, int weight>
    void LDPC<Size, weight>::View::swapCol(Idx& c0, Idx& c1)
    {
#ifdef LDPC_DEBUG
        assert(c0.mSrcIdx == colIdx(c0.mViewIdx).mSrcIdx);
        assert(c1.mSrcIdx == colIdx(c1.mViewIdx).mSrcIdx);
#endif

        std::swap(mColNOMap[c0.mViewIdx], mColNOMap[c1.mViewIdx]);
        std::swap(mColONMap[c0.mSrcIdx], mColONMap[c1.mSrcIdx]);
        std::swap(c0.mSrcIdx, c1.mSrcIdx);
    }


    template<typename Size, int weight>
    void LDPC<Size, weight>::View::popMinWeightRow(Idx& idx, size_type& i)
    {
        i = 1;
        for (; true; ++i)
        {
            if (mWeightSets[i] != mNullRow)
            {
                auto& weightSetHead = mWeightSets[i];
                idx.mSrcIdx = weightSetHead;
                idx.mViewIdx = mRowData[idx.mSrcIdx].mONMap;

#ifdef LDPC_STATS
                --mWeightSetSizes[i];
#endif
                auto& row = mRowData[weightSetHead];
                weightSetHead = row.mNextWeightNode;


                mRowData[weightSetHead].mPrevWeightNode = mNullRow;
                row.mWeight = 0;
                row.mNextWeightNode = mNullRow;
                return;
            }
        }
        throw RTE_LOC;
    }

    template<typename Size, int weight>
    void LDPC<Size, weight>::View::decRowWeight(size_type idx)
    {
        auto& row = mRowData[idx];
        auto w = row.mWeight--;
        assert(w);

        auto prev = row.mPrevWeightNode;
        auto next = row.mNextWeightNode;

        assert(next == mNullRow || mRowData[next].mPrevWeightNode == idx);
        assert(prev == mNullRow || mRowData[prev].mNextWeightNode == idx);

        TODO("first clause can always be performed.");
        if (prev != mNullRow)
        {
            mRowData[prev].mNextWeightNode = next;
        }
        else
        {
            assert(mWeightSets[w] == idx);
            mWeightSets[w] = next;
        }

        mRowData[next].mPrevWeightNode = prev;
        row.mPrevWeightNode = mNullRow;

        if (mWeightSets[w - 1] != mNullRow)
        {
            mRowData[mWeightSets[w - 1]].mPrevWeightNode = idx;
        }
        row.mNextWeightNode = mWeightSets[w - 1];
        mWeightSets[w - 1] = idx;

#ifdef LDPC_STATS
        --mWeightSetSizes[w];
        ++mWeightSetSizes[w - 1];
#endif

    }

    template<typename Size, int weight>
    typename LDPC<Size, weight>::RowVector LDPC<Size, weight>::View::applyPerm()const
    {
        RowVector newRows(mH->rows());
        applyPerm(newRows);
        return newRows;
    }


    template<typename Size, int weight>
    void LDPC<Size, weight>::View::applyPerm(RowSpan newRows)const
    {
        RowVector temp;
        RowSpan src = mH->mRows;
        if (newRows.data() == mH->mRows.data())
        {
            temp.insert(temp.end(), mH->mRows.begin(), mH->mRows.end());
            src = temp;
        }

        for (u64 i = 0; i < mH->mRows.size(); i++)
        {
            for (u64 j = 0; j < weight; ++j)
            {
                newRows[mRowData[i].mONMap][j] = mColONMap[src[i][j]];
            }
        }
    }

    template<typename Size, int weight>
    void LDPC<Size, weight>::insert(Size numCols, MatrixView<Size> rows)
    {
        mNumCols = numCols;
        if (rows.cols() != weight)
            throw RTE_LOC;

        mRows = span<Row>((Row*)rows.data(), rows.rows());

        auto numRows = rows.rows();
        auto numRows8 = (numRows / 8) * 8;

        auto size = rows.size();
        auto size8 = (size / 8) * 8;

        mColData.resize(rows.size());

        bool hadData = mBackingColStartIdxs.size() > 0;
        mBackingColStartIdxs.resize(numCols + 2);

        if (hadData)
            memset(mBackingColStartIdxs.data(), 0, mBackingColStartIdxs.size() * sizeof(Size));

        mColStartIdxs = span<Size>(mBackingColStartIdxs.data() + 1, mBackingColStartIdxs.size() - 1);

        auto rowsPtr = rows.data();
        auto counts = mColStartIdxs.data() + 1;

        // First we will count row mant rows are in any 
        // given column.
        for (u64 ii8 = 0; ii8 < size8; ii8 += 8)
        {
            auto col0 = rowsPtr[ii8 + 0];
            auto col1 = rowsPtr[ii8 + 1];
            auto col2 = rowsPtr[ii8 + 2];
            auto col3 = rowsPtr[ii8 + 3];
            auto col4 = rowsPtr[ii8 + 4];
            auto col5 = rowsPtr[ii8 + 5];
            auto col6 = rowsPtr[ii8 + 6];
            auto col7 = rowsPtr[ii8 + 7];

            assert(rowsPtr + ii8 + 7 < rows.data() + rows.size());
            assert(col0 < numCols);
            assert(col1 < numCols);
            assert(col2 < numCols);
            assert(col3 < numCols);
            assert(col4 < numCols);
            assert(col5 < numCols);
            assert(col6 < numCols);
            assert(col7 < numCols);

            ++counts[col0];
            ++counts[col1];
            ++counts[col2];
            ++counts[col3];
            ++counts[col4];
            ++counts[col5];
            ++counts[col6];
            ++counts[col7];
        }
        for (u64 i = size8; i < size; ++i)
        {
            auto col = rowsPtr[i];
            assert(rowsPtr + i < rows.data() + rows.size());
            assert(col < numCols);
            ++counts[col];
        }


        // Then we convert these counts into where
        // each column begins by iteratively summing 
        // over the values.
        for (u64 i = 1; i < mColStartIdxs.size(); ++i)
            mColStartIdxs[i] += mColStartIdxs[i - 1];

        // Now populate each column by iterting over the rows and
        // adding the non-zero row indices to the column.
        auto ptr = rows.data();
        for (u64 i8 = 0; i8 < numRows8; i8 += 8)
        {
            auto ptr0 = ptr + weight * 0;
            auto ptr1 = ptr + weight * 1;
            auto ptr2 = ptr + weight * 2;
            auto ptr3 = ptr + weight * 3;
            auto ptr4 = ptr + weight * 4;
            auto ptr5 = ptr + weight * 5;
            auto ptr6 = ptr + weight * 6;
            auto ptr7 = ptr + weight * 7;
            ptr += 8 * weight;

            for (u64 j = 0; j < weight; ++j)
            {
                auto col0 = *ptr0++;
                auto col1 = *ptr1++;
                auto col2 = *ptr2++;
                auto col3 = *ptr3++;
                auto col4 = *ptr4++;
                auto col5 = *ptr5++;
                auto col6 = *ptr6++;
                auto col7 = *ptr7++;

                // Here we are incrementing the start
                // index for each column. After all rows 
                // have been inserted, it will hold that
                //
                //  mColStartIdxs[i] = old mColStartIdxs[i-1]
                //
                // There, afterwards these values are still 
                // correct and we simply make mColStartIdxs
                // start one position earlier.
                auto p0 = mColStartIdxs[col0]++;
                auto p1 = mColStartIdxs[col1]++;
                auto p2 = mColStartIdxs[col2]++;
                auto p3 = mColStartIdxs[col3]++;
                auto p4 = mColStartIdxs[col4]++;
                auto p5 = mColStartIdxs[col5]++;
                auto p6 = mColStartIdxs[col6]++;
                auto p7 = mColStartIdxs[col7]++;

                mColData[p0] = i8 + 0;
                mColData[p1] = i8 + 1;
                mColData[p2] = i8 + 2;
                mColData[p3] = i8 + 3;
                mColData[p4] = i8 + 4;
                mColData[p5] = i8 + 5;
                mColData[p6] = i8 + 6;
                mColData[p7] = i8 + 7;
            }
        }

        for (u64 r = numRows8; r < numRows; ++r)
        {
            for (u64 j = 0; j < weight; ++j)
            {
                auto c = *ptr++;
                auto p = mColStartIdxs[c]++;
                mColData[p] = r;
            }
        }
        assert(ptr == rows.data() + rows.size());

        // Here we update mColStartIdxs since 
        // its now off by one after the loop.
        mColStartIdxs = span<Size>(mBackingColStartIdxs.data(), mBackingColStartIdxs.size() - 1);
    }


    template<typename Size, int weight>
    void LDPC<Size, weight>::blockTriangulate(
        std::vector<std::array<size_type, 3>>& blocks,
        std::vector<size_type>& rowPerm,
        std::vector<size_type>& colPerm,
        bool verbose,
        bool stats,
        bool apply)
    {

        size_type n = cols();
        size_type m = rows();

        // The current top row of the view.
        size_type i = 0;

        // The current left column of the view.
        size_type c = 0;


        static const size_type weightp1 = weight + 1;

        blocks.resize(0);

        // This will store the input column indices which we
        // we move to the left side of the view.
        std::array<size_type, weight> colSwapsSrc;

        // same as colSwapsSrc but holds the indices of columns in the view.
        std::array<size_type, weight> colSwapsView;
        size_type numColSwaps{ 0 };

        // We are going to create a 'view' over the matrix.
        // At each iterations we will move some of the rows 
        // and columns in the view to the top/left. These 
        // moved rows will then be excluded from the view.
        mView.init(*this);

#ifdef LDPC_VERBOSE
        std::unique_ptr<RowVector> HH;
        if (verbose) HH.reset(new RowVector(mRows.begin(), mRows.end()));
#endif

#ifdef LDPC_STATS
        std::array<double, weightp1> avgs;
        std::array<size_type, weightp1> max;
        u64 numSamples(0);
#endif

        while (GSL_LIKELY(i != m))
        {
            assert(i < m);
            assert(c < n);

#ifdef LDPC_STATS
            numSamples++;
            for (u64 j = 0; j < mView.mWeightSets.size(); ++j)
            {
                avgs[j] += mView.mWeightSetSizes[j];
                max[j] = std::max(max[j], mView.mWeightSetSizes[j]);
            }
#endif

            if (GSL_LIKELY(mView.mWeightSets[0] == mView.mNullRow))
            {
                // If we don't have any rows with hamming
                // weight 0 then we will pick the row with 
                // minimim hamming weight and move it to the
                // top of the view.
                Idx u;
                size_type wi;
                mView.popMinWeightRow(u, wi);

                // get the input row index of the i'th row in 
                // the view.
                Idx ii = mView.rowIdx(i);

                // move the min weight row u to row i.
                mView.swapRows(u, ii);

#ifdef LDPC_VERBOSE
                if (verbose) {
                    std::cout << "wi " << wi << std::endl;
                    std::cout << "swapRow(" << i << ", " << u.mViewIdx << ")" << std::endl;
                }
#endif
                // For this newly moved row i, we need to move all the 
                // columns where this row has a non-zero value to the
                // left side of the view. 


                // The non-zero columns in this row.
                auto rowi = mRows[ii.mSrcIdx];

                // we will collect all of the columns rowi which we
                // need to move left. 
                numColSwaps = 0;
                for (size_type j = 0; j < weight; ++j)
                {
                    Idx c0;
                    c0.mSrcIdx = rowi[j];
                    c0.mViewIdx = mView.mColONMap[c0.mSrcIdx];

                    // check if this column is inside the view.
                    if (c0.mViewIdx >= c)
                    {
                        // add this column to the set of columns that we will move.
                        colSwapsSrc[numColSwaps] = c0.mSrcIdx;
                        colSwapsView[numColSwaps] = c0.mViewIdx;
                        ++numColSwaps;
#ifdef LDPC_VERBOSE
                        if (verbose)
                            std::cout << "swapCol(" << c0.mViewIdx << ")" << std::endl;
#endif

                        // iterator over the rows for this column and decrement their row weight.
                        // we do this since we are about to move this column outside of the view.
                        auto b = &mColStartIdxs[c0.mSrcIdx];
                        size_type* col(mColData.data() + b[0]);
                        auto numCols = b[1] - b[0];

                        for (size_type k = 0; k < numCols; ++k)
                        {
                            // these a special case that this row is the u row which
                            // has already been decremented
                            if (col[k] != ii.mSrcIdx)
                            {
                                mView.decRowWeight(col[k]);
                            }
                        }
                    }
                }

                // now update the mappings so that these columns are
                // right before the view.
                while (numColSwaps)
                {
                    auto begin = colSwapsView.data();
                    auto end = colSwapsView.data() + numColSwaps;
                    auto back = end - 1;

                    auto srcBegin = colSwapsSrc.data();
                    auto srcBack = colSwapsSrc.data() + numColSwaps - 1;

                    auto sIter = std::find(begin, end, c);
                    if (sIter != end)
                    {
                        auto j = sIter - begin;
                        std::swap(*sIter, *back);
                        std::swap(srcBegin[j], *srcBack);
                    }
                    else
                    {
                        Idx bb{ *back, *srcBack };
                        auto cc = mView.colIdx(c);

                        std::swap(mView.mColNOMap[cc.mViewIdx], mView.mColNOMap[bb.mViewIdx]);
                        std::swap(mView.mColONMap[cc.mSrcIdx], mView.mColONMap[bb.mSrcIdx]);
                    }

                    ++c;
                    --numColSwaps;
                }

                // move the view down by 1
                ++i;
            }
            else
            {
                // in the case that we have some rows with
                // hamming weight 0, we will move all these
                // rows to the top of the view and remove them.
                auto rowPtr = mView.mWeightSets[0];
                mView.mWeightSets[0] = mView.mNullRow;
#ifdef LDPC_STATS
                mView.mWeightSetSizes[0] = 0;
#endif

                std::vector<RowData*> rows;
                while (rowPtr != mView.mNullRow)
                {
                    auto& row = mView.mRowData[rowPtr];
                    rows.push_back(&row);
                    rowPtr = row.mNextWeightNode;
                }

                size_type dk = rows.size();
                while (rows.size())
                {
                    // the actual input row index which we will 
                    // be swapping with.
                    auto r1SrcPtr = mView.mRowData.data() + mView.mRowData[i].mNOMap;


                    // check that there isn't already a row
                    // that we want at the top.
                    auto sIter = std::find(rows.begin(), rows.end(), r1SrcPtr);
                    auto viewIdx = i;

                    if (sIter == rows.end())
                    {
                        // if not then pick an arbitrary row
                        // that we will move to the top.
                        sIter = rows.begin();

                        Size inIdx = *sIter - mView.mRowData.data();
                        viewIdx = mView.mRowData[inIdx].mONMap;

                        Idx dest = mView.rowIdx(i);
                        Idx src = { viewIdx, inIdx };// mView.rowSrcIdx((**sIter));

                        mView.swapRows(dest, src);
                    }

#ifdef LDPC_VERBOSE
                    if (verbose)
                        std::cout << "rowSwap*(" << i << ", " << viewIdx << ")" << std::endl;
#endif

                    auto& row = **sIter;
                    row.mWeight = 0;
                    row.mNextWeightNode = mView.mNullRow;
                    row.mPrevWeightNode = mView.mNullRow;

                    rows.erase(sIter);
                    ++i;
                }

                // recode that this the end of the block.
                blocks.push_back({ Size(i), Size(c), dk });

#ifdef LDPC_VERBOSE
                if (verbose)
                {
                    std::cout << "RC " << blocks.back()[0] << " " << blocks.back()[1] << std::endl;
                    std::cout << "i " << (i ) << " = " << i - dk << " + " << dk << std::endl;
                }
#endif
            }

#ifdef LDPC_VERBOSE
            if (verbose)
            {
                auto bb = blocks;
                bb.push_back({ i, Size(c), 0 });
                RowVector W = mView.applyPerm();


                std::vector<size_type> weights(rows());
                std::vector<std::string> ids(rows());
                for (u64 i = 0; i < weights.size(); ++i)
                {
                    weights[i] = mView.mRowData[mView.mRowData[i].mNOMap].mWeight;
                    ids[i] = std::to_string(mView.mRowData[i].mNOMap) + " " + std::to_string(i);
                }

                std::cout << "\n" << diff<RowSpan, Size>(W, *HH, bb, cols(), &weights, &ids) << std::endl
                    << "=========================================\n"
                    << std::endl;

                *HH = std::move(W);
            }
#endif
        }

        auto numRows = mView.mRowData.size();
        rowPerm.resize(numRows);
        for (u64 i = 0; i < numRows; ++i)
            rowPerm[i] = mView.mRowData[i].mONMap;
        colPerm = mView.mColONMap;

        if (apply)
        {
            mView.applyPerm(mRows);
        }

#ifdef LDPC_STATS
        if (stats)
        {

            for (u64 j = 0; j < avgs.size(); ++j)
            {
                std::cout << j << " avg  " << avgs[j] / numSamples << "  max  " << max[j] << std::endl;
            }
            std::array<size_type, 3> prev = {};
            for (u64 j = 0; j < blocks.size(); ++j)
            {
                if (j == 10 && blocks.size() > 20)
                {
                    std::cout << "..." << std::endl;
                    j = blocks.size() - 10;
                }

                std::cout << "RC[" << j << "] " << (blocks[j][0] - prev[0]) << " " << (blocks[j][1] - prev[1]) << "  ~   " << blocks[j][2] << std::endl;
                prev = blocks[j];
            }

            if (prev[0] != mRows.size())
            {
                std::cout << "RC[" << blocks.size() << "] " << (mRows.size() - prev[0]) << " " << (mNumCols - prev[1]) << "  ~   0" << std::endl;
            }
        }
#endif
    }

    template class LDPC<u64, 2>;
    template class LDPC<u32, 2>;
    template class LDPC<u16, 2>;
    template class LDPC<u64, 3>;
    template class LDPC<u32, 3>;
    template class LDPC<u16, 3>;


    template class LDPC<u64, 10>;
    template class LDPC<u32, 10>;
    template class LDPC<u16, 10>;
    //template class LDPC<u8>;
}