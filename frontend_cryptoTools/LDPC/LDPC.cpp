

#define LDPC_DEBUG

#ifndef LDPC_DEBUG
    #define NDEBUG
#endif

//#define VERBOSE

#include "LDPC.h"
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

        return o;
    }

    template<typename Size>
    void LDPC<Size>::View::init(LDPC<Size>& b)
    {
        //mH(b)
        mH = &b;
        mRowData.resize(b.rows()+ 1);
        mNullRow = b.rows();

        mWeightSets.resize(0);
        mWeightSets.resize(b.rowWeight() + 1, mNullRow);
        mColNOMap.resize(b.cols());
        mColONMap.resize(b.cols());

        auto w = b.rowWeight();
        auto nn = mRowData.size();
        auto row = mRowData.data();
        for (u64 i = 0; i <nn; ++i)
        {
            row[0].mNOMap = i;
            row[0].mONMap = i;
            row[0].mPrevWeightNode = i - 1;
            row[0].mNextWeightNode = i + 1;
            row[0].mWeight = w;
            ++row;
        }

        mRowData.front().mPrevWeightNode = mNullRow;
        mRowData.back().mNextWeightNode = mNullRow;
        mWeightSets.back() = 0;

        for (u64 i = 0; i < mColNOMap.size(); ++i)
            mColNOMap[i] = mColONMap[i] = i;
    }

    template<typename Size>
    void LDPC<Size>::View::swapRows(Idx& r0, Idx& r1)
    {
#ifdef LDPC_DEBUG
        assert(r0.mSrcIdx == rowIdx(r0.mViewIdx).mSrcIdx);
        assert(r1.mSrcIdx == rowIdx(r1.mViewIdx).mSrcIdx);
#endif

        std::swap(mRowData[r0.mViewIdx].mNOMap, mRowData[r1.mViewIdx].mNOMap);
        std::swap(mRowData[r0.mSrcIdx].mONMap, mRowData[r1.mSrcIdx].mONMap);
        std::swap(r0.mSrcIdx, r1.mSrcIdx);
    }

    template<typename Size>
    void LDPC<Size>::View::swapCol(Idx& c0, Idx& c1)
    {
#ifdef LDPC_DEBUG
        assert(c0.mSrcIdx == colIdx(c0.mViewIdx).mSrcIdx);
        assert(c1.mSrcIdx == colIdx(c1.mViewIdx).mSrcIdx);
#endif

        std::swap(mColNOMap[c0.mViewIdx], mColNOMap[c1.mViewIdx]);
        std::swap(mColONMap[c0.mSrcIdx], mColONMap[c1.mSrcIdx]);
        std::swap(c0.mSrcIdx, c1.mSrcIdx);
    }


    template<typename Size>
    std::pair<typename LDPC<Size>::Idx, Size> LDPC<Size>::View::popMinWeightRow()
    {
        Idx idx;
        for (u64 i = 1; i < mWeightSets.size(); ++i)
        {
            if (mWeightSets[i] != mNullRow)
            {
                auto& weightSetHead = mWeightSets[i];
                auto& row = mRowData[weightSetHead];
                idx.mSrcIdx = weightSetHead;

                weightSetHead = row.mNextWeightNode;


                mRowData[weightSetHead].mPrevWeightNode = mNullRow;
                //TODO("remove this if statement by making an actual NULL_NODE")
                //if (weightSetHead != NULL_NODE)
                //{
                //    mRowData[weightSetHead].mPrevWeightNode = mNullRow;
                //}


                idx.mViewIdx = mRowData[idx.mSrcIdx].mONMap;
                row.mWeight = 0;
                row.mNextWeightNode = mNullRow;

                return { idx, i };
            }
        }

        //for (u64 i = 0; i < mBigWeightSets.size(); i++)
        //{
        //    if (mBigWeightSets[i].size())
        //    {
        //        auto iter = mBigWeightSets[i].begin();
        //        idx.mSrcIdx = *iter;
        //        idx.mIdx = mRowONMap[idx.mSrcIdx];
        //        mBigWeightSets[i].erase(iter);
        //        mRowWeights[idx.mSrcIdx] = 0;
        //        return { idx, i + mSmallWeightSets.size() };
        //    }
        //}

        throw RTE_LOC;
    }

    template<typename Size>
    void LDPC<Size>::View::decRowWeight(const Idx& idx)
    {
        //assert(idx.mSrcIdx == rowIdx(idx.mIdx).mSrcIdx);
        auto& row = mRowData[idx.mSrcIdx];
        auto w = row.mWeight--;
#ifdef LDPC_DEBUG
        assert(w);
#endif

        auto prev = row.mPrevWeightNode;
        auto next = row.mNextWeightNode;

#ifdef LDPC_DEBUG
        assert(next == mNullRow || mRowData[next].mPrevWeightNode == idx.mSrcIdx);
        assert(prev == mNullRow || mRowData[prev].mNextWeightNode == idx.mSrcIdx);
#endif

        TODO("first clause can always be performed.");
        if (prev != mNullRow)
        {
            mRowData[prev].mNextWeightNode = next;
        }
        else
        {
#ifdef LDPC_DEBUG
            assert(mWeightSets[w] == idx.mSrcIdx);
#endif
            mWeightSets[w] = next;
        }

        mRowData[next].mPrevWeightNode = prev;
        row.mPrevWeightNode = mNullRow;

        TODO("can always be performed?????");
        if (mWeightSets[w - 1] != mNullRow)
        {
           mRowData[mWeightSets[w - 1]].mPrevWeightNode = idx.mSrcIdx;
        }
        row.mNextWeightNode = mWeightSets[w - 1];
        mWeightSets[w - 1] = idx.mSrcIdx;

    }

    template<typename Size>
    Matrix<Size> LDPC<Size>::View::applyPerm()const
    {
        Matrix<Size> newRows(mH->rows(), mH->rowWeight());
        applyPerm(newRows);
        return newRows;
        //mH->mRows = std::move(newRows);

        //std::vector<u64> newCols(mH->mColData.size());
        //std::vector<u64> colStartIdxs(mH->cols() + 1);
        //for (u64 i = 0, c = 0; i < mH->cols(); ++i)
        //{
        //    auto oIdx = mColNOMap[i];
        //    auto b = mH->mColStartIdxs[oIdx];
        //    auto e = mH->mColStartIdxs[oIdx + 1];
        //    colStartIdxs[i + 1] = colStartIdxs[i] + (e - b);

        //    while (b < e)
        //    {
        //        newCols[c++] = mRowData[mH->mColData[b++]].mONMap;
        //    }
        //}
        //mH->mColStartIdxs = std::move(colStartIdxs);
        //mH->mColData = std::move(newCols);
    }

    template<typename Size>
    void LDPC<Size>::View::applyPerm(MatrixView<Size> newRows)const
    {
        Matrix<Size> temp;
        MatrixView<Size> src = mH->mRows;
        if (newRows.data() == src.data())
        {
            temp = src;
            src = temp;
        }

        for (u64 i = 0; i < mH->mRows.rows(); i++)
        {
            for (u64 j = 0; j < mH->mRows.cols(); ++j)
            {
                newRows(mRowData[i].mONMap, j) = mColONMap[src(i, j)];
            }
        }
    }

    template<typename Size>
    LDPC<Size>::RowIter::RowIter(View& H, const Idx& i, Size p)
        : mH(H)
        , mRow(H.mH->mRows[i.mSrcIdx])
        , mPos(p)
    { }


    template<typename Size>
    typename LDPC<Size>::Idx LDPC<Size>::RowIter::operator*()
    {
        Idx idx;
        idx.mSrcIdx = mRow[mPos];
        idx.mViewIdx = mH.mColONMap[idx.mSrcIdx];
        return idx;
    }

    template<typename Size>
    void LDPC<Size>::RowIter::operator++()
    {
        ++mPos;
    }
    template<typename Size>

    LDPC<Size>::ColIter::ColIter(View& H, const Idx& i, Size p)
        : mH(H)
        , mCol(H.mH->col(i.mSrcIdx))
        , mPos(p)
    { }

    template<typename Size>
    void LDPC<Size>::ColIter::operator++()
    {
        ++mPos;
    }

    template<typename Size>
    typename LDPC<Size>::Idx LDPC<Size>::ColIter::operator*()
    {
        Idx idx;
        idx.mSrcIdx = mCol[mPos];
        idx.mViewIdx = mH.mRowData[idx.mSrcIdx].mONMap;
        return idx;
    }

    template<typename Size>
    Size LDPC<Size>::ColIter::srcIdx()
    {
        return mCol[mPos];
    }

    template<typename Size>
    LDPC<Size>::ColIter::operator bool()
    {
        return mPos < mCol.size();
    }
//}
//
//namespace std
//{
//    template<typename Size>
//    struct hash<oc::LDPC<Size>::Idx>
//    {
//        std::size_t operator()(oc::LDPC::Idx const& i) const noexcept
//        {
//            return i.mViewIdx;
//        }
//    };
//}
//
//namespace osuCrypto
//{

    template<typename Size>
    void LDPC<Size>::insert(Size numCols, MatrixView<Size> rows)
    {
        mNumCols = numCols;
        mRows = rows;
        auto numRows = rows.rows();
        auto numRows8 = (numRows / 8) * 8;

        auto size = rows.size();
        auto size8 = (size / 8) * 8;
        auto weight = rows.cols();

        mColData.resize(rows.size());

        bool hadData = mBackingColStartIdxs.size() > 0;
        mBackingColStartIdxs.resize(numCols + 2);

        if (hadData)
            memset(mBackingColStartIdxs.data(), 0, mBackingColStartIdxs.size() * sizeof(Size));



        mColStartIdxs = span<Size>(mBackingColStartIdxs.data() + 1, mBackingColStartIdxs.size() - 1);

        //for (auto& col : rows)
        //    ++mColStartIdxs[col + 1];
        auto rowsPtr = rows.data();
        auto counts = mColStartIdxs.data() + 1;

        for (u64 i8 = 0; i8 < size8; i8 += 8)
        {
            auto col0 = rowsPtr[i8 + 0];
            auto col1 = rowsPtr[i8 + 1];
            auto col2 = rowsPtr[i8 + 2];
            auto col3 = rowsPtr[i8 + 3];
            auto col4 = rowsPtr[i8 + 4];
            auto col5 = rowsPtr[i8 + 5];
            auto col6 = rowsPtr[i8 + 6];
            auto col7 = rowsPtr[i8 + 7];

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
            ++counts[col];
        }


        for (u64 i = 1; i < mColStartIdxs.size(); ++i)
            mColStartIdxs[i] += mColStartIdxs[i - 1];

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

        mColStartIdxs = span<Size>(mBackingColStartIdxs.data(), mBackingColStartIdxs.size() - 1);
    }

    template<typename Size>
    void LDPC<Size>::blockTriangulate(
        std::vector<std::array<size_type, 3>>& blocks,
        std::vector<size_type>& rowPerm,
        std::vector<size_type>& colPerm,
        bool verbose,
        bool stats,
        bool apply)
    {

        size_type n = cols();
        size_type m = rows();
        size_type k = 0;
        size_type i = 0;
        size_type v = n;
        size_type weight = rowWeight();
        size_type weightp1 = weight + 1;
        blocks.resize(0);


        // temps
        std::vector<size_type> colSwapsSrc(weight);
        std::vector<size_type> colSwapsView(weight);
        size_type numColSwaps{ 0 };

        // We are going to create a 'view' over the matrix.
        // At each iterations we will move some of the rows 
        // and columns in the view to the top/left. These 
        // moved rows will then be excluded from the view.
        // 
        //View H(*this);
        mView.init(*this);

#ifdef VERBOSE
        std::unique_ptr<Matrix<size_type>> HH;
        if (verbose)
        {
            HH.reset(new Matrix<size_type>(mRows));
        }
#endif
        //std::vector<double> avgs(rowWeight() + 1);
        //std::vector<u64> max(rowWeight() + 1);
        //u64 numSamples(0);

        while (GSL_LIKELY(i < m && v))
        {
            //numSamples++;
            //for (u64 j = 0; j < mView.mWeightSets.size(); ++j)
            //{
            //    avgs[j] += mView.mWeightSets[j].size();
            //    max[j] = std::max(max[j], mView.mSmallWeightSets[j].size());
            //}

            //for (u64 j = 0; j < mView.mBigWeightSets.size(); ++j)
            //{
            //    auto jj = j + mView.mSmallWeightSets.size();
            //    avgs[jj] += mView.mBigWeightSets[j].size();
            //    max[jj] = std::max(max[jj], mView.mBigWeightSets[j].size());
            //}

            if (GSL_LIKELY(mView.mWeightSets[0] == mView.mNullRow))
            {
                // If we don't have any rows with hamming
                // weight 0 then we will pick the row with 
                // minimim hamming weight and move it to the
                // top of the view.
                //auto uu = mView.popMinWeightRow();
                //auto u = uu.first;
                //auto wi = uu.second;
                Idx u;
                size_type wi = 1;
                for (; wi < weightp1; ++wi)
                {
                    if (mView.mWeightSets[wi] != mView.mNullRow)
                    {
                        auto& weightSetHead = mView.mWeightSets[wi];
                        auto& row = mView.mRowData[weightSetHead];
                        u.mSrcIdx = weightSetHead;

                        weightSetHead = row.mNextWeightNode;
                        mView.mRowData[weightSetHead].mPrevWeightNode = mView.mNullRow;
                        u.mViewIdx = mView.mRowData[u.mSrcIdx].mONMap;
                        //row.mWeight = 0;
                        //row.mNextWeightNode = mView.mNullRow;
                        break;
                    }
                }


                // move the min weight row u to row i.
                auto ii = mView.rowIdx(i);
                mView.swapRows(u, ii);

#ifdef VERBOSE
                if (verbose) {
                    std::cout << "wi " << wi << std::endl;
                    std::cout << "swapRow(" << i << ", " << u.mViewIdx << ")" << std::endl;
                }
#endif
                // For this newly moved row i, we need to move all the 
                // columns where this row has a non-zero value to the
                // left side of the view. 

                // c1 is the column defining the left side of the view
                auto c1 = (n - v);

                // rIter iterates the columns which have non-zero values for row ii.
                //auto rIter = mView.rowIterator(ii);
                //auto rIter = RowIter(mView, ii, 0);

                auto rowi = mRows.data() + ii.mSrcIdx * weight;

                // this set will collect all of the columns in the view. 
                //colSwaps.clear();
                numColSwaps = 0;
                for (size_type j = 0; j < weight; ++j)
                {
                    //auto c0 = colIdx[j];
                    //auto c0 = *rIter;

                    Idx c0;
                    c0.mSrcIdx = rowi[j];
                    c0.mViewIdx = mView.mColONMap[c0.mSrcIdx];

                    //++rIter;

                    // check if this column is inside the view.
                    if (c0.mViewIdx >= c1)
                    {
                        // add this column to the set of columns that we will move.
                        colSwapsSrc[numColSwaps] = c0.mSrcIdx;
                        colSwapsView[numColSwaps] = c0.mViewIdx;
                        ++numColSwaps;
                        //colSwaps.push_back(c0);
#ifdef VERBOSE
                        if (verbose)
                            std::cout << "swapCol(" << c0.mViewIdx << ")" << std::endl;
#endif

                        // iterator over the rows for this column and decrement their row weight.
                        // we do this since we are about to move this column outside of the view.
                        //auto cIter = mView.colIterator(c0);
                        //auto cIter = ColIter(mView, c0, 0);
                        //auto col = mView.mH->col(c0.mSrcIdx);
                        auto b = &mColStartIdxs[c0.mSrcIdx];
                        span<size_type> col(mColData.data() + b[0], b[1] - b[0]);


                        auto numCols = col.size();
                        for (size_type k = 0; k < numCols; ++k)
                        {
                            // these a special case that this row is the u row which
                            // has already been decremented
                            if (col[k] != ii.mSrcIdx)
                            {
                                //Idx idx;
                                auto idx = col[k];
                                //idx.mViewIdx = mView.mRowData[col[k]].mONMap;
                                //mView.decRowWeight(idx);
                                {
                                    auto& row = mView.mRowData[idx];
                                    auto w = row.mWeight--;

                                    auto prev = row.mPrevWeightNode;
                                    auto next = row.mNextWeightNode;

                                    mView.mRowData[prev].mNextWeightNode = next;

                                    //TODO("first clause can always be performed");
                                    if (prev == mView.mNullRow)
                                    {
                                        //assert(mWeightSets[w] == &row);
                                        mView.mWeightSets[w] = next;
                                    }
                                    //mView.mWeightSets[w] ^=
                                    //    (prev == mView.mNullRow) * (next ^ mView.mWeightSets[w]);

                                    mView.mRowData[next].mPrevWeightNode = prev;
                                    row.mPrevWeightNode = mView.mNullRow;

                                    //TODO("can always be performed????");
                                    if (mView.mWeightSets[w - 1] != mView.mNullRow)
                                    {
                                        mView.mRowData[mView.mWeightSets[w - 1]].mPrevWeightNode = idx;
                                    }
                                    //mView.mRowData[mView.mWeightSets[w - 1]].mPrevWeightNode = idx.mSrcIdx;

                                    row.mNextWeightNode = mView.mWeightSets[w - 1];
                                    mView.mWeightSets[w - 1] = idx;
                                }
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

                    //auto cc = c1++;
                    auto sIter = std::find(begin, end, c1);
                    if (sIter != end)
                    {
                        auto j = sIter - begin;
                        std::swap(*sIter, *back);
                        std::swap(srcBegin[j], *srcBack);
                    }
                    else
                    {
                        Idx bb{ *back, *srcBack };
                        auto cc = mView.colIdx(c1);

                        std::swap(mView.mColNOMap[cc.mViewIdx], mView.mColNOMap[bb.mViewIdx]);
                        std::swap(mView.mColONMap[cc.mSrcIdx], mView.mColONMap[bb.mSrcIdx]);
                        //mView.swapCol(cc, bb);
                    }

                    ++c1;
                    --numColSwaps;
                    //colSwaps.pop_back();
                }

#ifdef VERBOSE
                if (verbose)
                {
                    std::cout << "v " << (v - wi) << " = " << v << " - " << wi << std::endl;
                    std::cout << "i " << (i + 1) << " = " << i << " + 1" << std::endl;
                }
#endif
                // move the view right by wi.
                v = v - wi;

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

                std::vector<RowData*> rows;
                while (rowPtr != mView.mNullRow)
                {
                    auto& row = mView.mRowData[rowPtr];
                    rows.push_back(&row);
                    rowPtr = row.mNextWeightNode;
                }

                size_type dk = 0;

                // the top of the view where we will be moving
                // the rows too.
                size_type c1 = i;

                while (rows.size())
                {
                    ++dk;

                    // the actual input row index which we will 
                    // be swapping with.
                    auto c1SrcPtr = mView.mRowData.data() + mView.mRowData[c1].mNOMap;


                    // check that there isn't already a row
                    // that we want at the top.
                    auto sIter = std::find(rows.begin(), rows.end(), c1SrcPtr);
                    auto viewIdx = c1;

                    if (sIter == rows.end())
                    {
                        // if not then pick an arbitrary row
                        // that we will move to the top.
                        sIter = rows.begin();

                        Size inIdx = *sIter - mView.mRowData.data();
                        viewIdx = mView.mRowData[inIdx].mONMap;

                        Idx dest = mView.rowIdx(c1);
                        Idx src = { viewIdx, inIdx };// mView.rowSrcIdx((**sIter));

                        mView.swapRows(dest, src);
                    }

#ifdef VERBOSE
                    if (verbose)
                        std::cout << "rowSwap*(" << c1 << ", " << viewIdx << ")" << std::endl;
#endif

                    auto& row = **sIter;
                    row.mWeight = 0;
                    row.mNextWeightNode = mView.mNullRow;
                    row.mPrevWeightNode = mView.mNullRow;

                    rows.erase(sIter);
                    ++c1;
                }

                // recode that this the end of the block.
                blocks.push_back({ Size(i + dk), Size(n - v), dk });
                //dks.push_back(dk);

#ifdef VERBOSE
                if (verbose)
                {
                    std::cout << "RC " << blocks.back()[0] << " " << blocks.back()[1] << std::endl;
                    std::cout << "i " << (i + dk) << " = " << i << " + " << dk << std::endl;
                    std::cout << "k " << (k + 1) << " = " << k << " + 1" << std::endl;
                }
#endif

                i += dk;
                ++k;
            }

#ifdef VERBOSE
            if (verbose)
            {
                auto bb = blocks;
                bb.push_back({ i, Size(n - v) });
                Matrix<size_type> W = mView.applyPerm();;


                std::vector<size_type> weights(rows());
                std::vector<std::string> ids(rows());
                for (u64 i = 0; i < weights.size(); ++i)
                {
                    weights[i] = mView.mRowData[mView.mRowData[i].mNOMap].mWeight;
                    ids[i] = std::to_string(mView.mRowData[i].mNOMap) + " " + std::to_string(i);
                }

                std::cout << "\n" << diff(W, *HH, bb, cols(), &weights, &ids) << std::endl
                    << "=========================================\n"
                    << std::endl;

                *HH = std::move(W);
            }
#endif
        }

        //R.push_back(m);
        //C.push_back(n);

        auto numRows = mView.mRowData.size();
        rowPerm.resize(numRows);
        for (u64 i = 0; i < numRows; ++i)
            rowPerm[i] = mView.mRowData[i].mONMap;
        colPerm = mView.mColONMap;

        if (apply)
            mView.applyPerm(mRows);

        //if (stats)
        //{

        //    for (u64 j = 0; j < avgs.size(); ++j)
        //    {
        //        std::cout << j << " avg  " << avgs[j] / numSamples << "  max  " << max[j] << std::endl;
        //    }
        //    std::array<u64, 3> prev = {};
        //    for (u64 j = 0; j < blocks.size(); ++j)
        //    {
        //        if (j == 50 && blocks.size() > 150)
        //        {
        //            std::cout << "..." << std::endl;
        //            j = blocks.size() - 50;
        //        }


        //        std::string dk;
        //        //if (i < dks.size())
        //        //    dk = std::to_string(dks[i]);

        //        std::cout << "RC[" << j << "] " << (blocks[j][0] - prev[0]) << " " << (blocks[j][1] - prev[1]) << "  ~   " << dk << std::endl;
        //        prev = blocks[j];
        //    }

        //    if (prev[0] != mRows.rows())
        //    {
        //        std::cout << "RC[" << blocks.size() << "] " << (mRows.rows() - prev[0]) << " " << (mNumCols - prev[1]) << "  ~   0" << std::endl;
        //    }
        //}

        //*this = applyPerm(mView.mRowONMap, mView.mColONMap);
    }

    template<typename Size>
    void LDPC<Size>::validate()
    {
        for (u64 i = 0; i < rows(); ++i)
        {
            for (u64 j = 0; j < rowWeight(); ++j)
            {
                auto cIdx = mRows(i, j);
                auto c = col(cIdx);

                if (c.size() != 0 && std::find(c.begin(), c.end(), i) == c.end())
                    throw RTE_LOC;
            }
        }
    }



    template class LDPC<u64>;
    template class LDPC<u32>;
    template class LDPC<u16>;
    template class LDPC<u8>;
}