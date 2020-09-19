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
#include "../cpp-btree/btree/set.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include <unordered_set>
//#include "absl/container/btree_set.h"
//#include "absl/container/flat_hash_set.h"
//#include "absl/container/node_hash_set.h"

#define LDPC_DEBUG

namespace osuCrypto
{


    void print(std::ostream& o, const Matrix<u64>& rows, u64 cols)
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

    std::ostream& operator<<(std::ostream& o, const LDPC& s)
    {
        print(o, s.mRows, s.cols());
        return o;
    }


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

    std::ostream& operator<<(std::ostream& o, const diff& s)
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
            for (u64 j = 0; j < s.mL.cols(); ++j)
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

            if (s.mWeights)
                o << "   " << (*s.mWeights)[i];
            o << "\n";
        }

        return o;
    }

    struct View
    {
        struct Idx
        {
            u64 mIdx, mSrcIdx;

            bool operator==(Idx const& y) const
            {
                if (mIdx == y.mIdx)
                {
                    assert(mSrcIdx == y.mSrcIdx);
                }
                else
                    assert(mSrcIdx != y.mSrcIdx);


                return mIdx == y.mIdx;
            }
        };

        struct RowIter
        {
            View& mH;
            span<u64> mRow;
            u64 mPos;

            RowIter(View& H, const Idx& i, u64 p)
                : mH(H)
                , mRow(H.mH.mRows[i.mSrcIdx])
                , mPos(p)
            { }

            void operator++()
            {
                ++mPos;
            }

            Idx operator*()
            {
                Idx idx;
                idx.mSrcIdx = mRow[mPos];
                idx.mIdx = mH.mColONMap[idx.mSrcIdx];
                return idx;
            }
        };

        struct ColIter
        {
            View& mH;
            span<u64> mCol;
            u64 mPos;

            ColIter(View& H, const Idx& i, u64 p)
                : mH(H)
                , mCol(H.mH.col(i.mSrcIdx))
                , mPos(p)
            { }

            void operator++()
            {
                ++mPos;
            }

            Idx operator*()
            {
                Idx idx;
                idx.mSrcIdx = mCol[mPos];
                idx.mIdx = mH.mRowONMap[idx.mSrcIdx];
                return idx;
            }

            u64 srcIdx()
            {
                return mCol[mPos];
            }

            operator bool()
            {
                return mPos < mCol.size();
            }
        };
        std::vector<u64> mRowNOMap, mRowONMap, mColNOMap, mColONMap;
        LDPC& mH;

        // a mapping from rIter IDX to current weight
        std::vector<u64> mRowWeights;// (m, mRows.cols());

        std::array<std::vector<u64>, 2> mSmallWeightSets;
        std::vector<btree::set<u64>> mBigWeightSets;

        View(LDPC& b)
            : mH(b)
            , mRowNOMap(b.rows())
            , mRowONMap(b.rows())
            , mColNOMap(b.cols())
            , mColONMap(b.cols())
            , mRowWeights(b.rows(), b.rowWeight())
        {
            // a mapping from a given weight to all rows that have that weight.
            mBigWeightSets.resize(b.rowWeight() + 1 - mSmallWeightSets.size());
            mSmallWeightSets[0].reserve(10);
            mSmallWeightSets[1].reserve(40);
            for (u64 i = 0; i < b.rows(); ++i)
                mBigWeightSets.back().insert(i);

            for (u64 i = 0; i < mRowNOMap.size(); ++i)
                mRowNOMap[i] = mRowONMap[i] = i;

            for (u64 i = 0; i < mColNOMap.size(); ++i)
                mColNOMap[i] = mColONMap[i] = i;
        }

        void swapRows(Idx& r0, Idx& r1)
        {
            assert(r0.mSrcIdx == rowIdx(r0.mIdx).mSrcIdx);
            assert(r1.mSrcIdx == rowIdx(r1.mIdx).mSrcIdx);

            std::swap(mRowNOMap[r0.mIdx], mRowNOMap[r1.mIdx]);
            std::swap(mRowONMap[r0.mSrcIdx], mRowONMap[r1.mSrcIdx]);
            std::swap(r0.mSrcIdx, r1.mSrcIdx);
        }

        void swapCol(Idx& c0, Idx& c1)
        {
            assert(c0.mSrcIdx == colIdx(c0.mIdx).mSrcIdx);
            assert(c1.mSrcIdx == colIdx(c1.mIdx).mSrcIdx);

            std::swap(mColNOMap[c0.mIdx], mColNOMap[c1.mIdx]);
            std::swap(mColONMap[c0.mSrcIdx], mColONMap[c1.mSrcIdx]);
            std::swap(c0.mSrcIdx, c1.mSrcIdx);
        };

        u64 rowWeight(u64 r)
        {
            return mRowWeights[mRowNOMap[r]];
        }

        Idx rowIdx(u64 viewIdx)
        {
            return { viewIdx, mRowNOMap[viewIdx] };
        }
        Idx rowSrcIdx(u64 viewIdx)
        {
            return { mRowONMap[viewIdx], viewIdx };
        }
        Idx colIdx(u64 viewIdx)
        {
            return { viewIdx, mColNOMap[viewIdx] };
        }

        RowIter rowIterator(const Idx& row)
        {
            assert(row.mSrcIdx == rowIdx(row.mIdx).mSrcIdx);

            return RowIter(*this, row, 0);
        }

        ColIter colIterator(const Idx& col)
        {
            assert(col.mSrcIdx == colIdx(col.mIdx).mSrcIdx);
            return ColIter(*this, col, 0);
        }

        std::pair<Idx, u64> popMinWeightRow()
        {
            Idx idx;
            for (u64 i = 1; i < mSmallWeightSets.size(); ++i)
            {
                if (mSmallWeightSets[i].size())
                {
                    idx.mSrcIdx = mSmallWeightSets[i].back();
                    mSmallWeightSets[i].pop_back();
                    idx.mIdx = mRowONMap[idx.mSrcIdx];
                    mRowWeights[idx.mSrcIdx] = 0;
                    return { idx, i };
                }
            }

            for (u64 i = 0; i < mBigWeightSets.size(); i++)
            {
                if (mBigWeightSets[i].size())
                {
                    auto iter = mBigWeightSets[i].begin();
                    idx.mSrcIdx = *iter;
                    idx.mIdx = mRowONMap[idx.mSrcIdx];
                    mBigWeightSets[i].erase(iter);
                    mRowWeights[idx.mSrcIdx] = 0;
                    return { idx, i + mSmallWeightSets.size() };
                }
            }

            throw RTE_LOC;
        }

        void decRowWeight(const Idx& idx)
        {
            //assert(idx.mSrcIdx == rowIdx(idx.mIdx).mSrcIdx);
            auto w = mRowWeights[idx.mSrcIdx]--;
            if (w > 1)
            {
                auto i = w - mSmallWeightSets.size();

                auto iter = mBigWeightSets[i].find(idx.mSrcIdx);
                assert(iter != mBigWeightSets[i].end());
                mBigWeightSets[i].erase(iter);

                if (i)
                    mBigWeightSets[i - 1].insert(idx.mSrcIdx);
                else
                    mSmallWeightSets.back().push_back(idx.mSrcIdx);
            }
            else
            {
                assert(w);
                auto iter = std::find(mSmallWeightSets[w].begin(), mSmallWeightSets[w].end(), idx.mSrcIdx);
                assert(iter != mSmallWeightSets[w].end());
                std::swap(mSmallWeightSets[w].back(), *iter);
                mSmallWeightSets[w].pop_back();
                mSmallWeightSets[w - 1].push_back(idx.mSrcIdx);
            }
        }

        void applyPerm(LDPC& H)
        {
            Matrix<u64> newRows(H.rows(), H.rowWeight());
            for (u64 i = 0; i < H.mRows.rows(); i++)
            {
                for (u64 j = 0; j < H.mRows.cols(); ++j)
                {
                    newRows(mRowONMap[i], j) = mColONMap[H.mRows(i, j)];
                }
            }
            H.mRows = std::move(newRows);

            std::vector<u64> newCols(H.mColData.size());
            std::vector<u64> colStartIdxs(H.cols() + 1);
            for (u64 i = 0, c = 0; i < H.cols(); ++i)
            {
                auto oIdx = mColNOMap[i];
                auto b = H.mColStartIdxs[oIdx];
                auto e = H.mColStartIdxs[oIdx + 1];
                colStartIdxs[i + 1] = colStartIdxs[i] + (e - b);

                while (b < e)
                {
                    newCols[c++] = mRowONMap[H.mColData[b++]];
                }
            }
            H.mColStartIdxs = std::move(colStartIdxs);
            H.mColData = std::move(newCols);
        }

    };

}

namespace std
{
    template<> struct hash<oc::View::Idx>
    {
        std::size_t operator()(oc::View::Idx const& i) const noexcept
        {
            return i.mIdx;
        }
    };
}

namespace osuCrypto
{

    void LDPC::insert(u64 rows, u64 cols, u64 rowWeight, std::vector<std::array<u64, 2>>& points)
    {
        if (rows * rowWeight != points.size())
            throw RTE_LOC;

        mNumCols = cols;
        mRows.resize(0, 0);
        mRows.resize(rows, rowWeight);
        memset(mRows.data(), -1, mRows.size() * sizeof(u64));

        mColData.clear();
        mColData.resize(rows * rowWeight);
        memset(mColData.data(), -1, mColData.size() * sizeof(u64));
        mColStartIdxs.resize(cols + 1);

        for (auto& p : points)
            ++mColStartIdxs[p[1] + 1];

        for (u64 i = 1; i < mColStartIdxs.size(); ++i)
            mColStartIdxs[i] += mColStartIdxs[i - 1];
        std::vector<u64> colPos(mColStartIdxs.begin(), mColStartIdxs.end()), rowPos(rows);

        for (auto& p : points)
        {
            auto r = p[0];
            auto c = p[1];

            if (rowPos[r] >= mRows.cols())
            {
                std::stringstream ss; ss << "only " << mRows.cols() << "items can be added to a row";
                throw std::runtime_error(ss.str());
            }
            mRows(r, rowPos[r]++) = c;
            //col(c)[colPos[c]++] = r;
            mColData[colPos[c]++] = r;
        }
    }

    void LDPC::blockTriangulate(
        std::vector<std::array<u64,3>>& blocks, 
        std::vector<u64>& rowPerm, 
        std::vector<u64>& colPerm, 
        bool verbose, 
        bool stats, 
        bool apply)
    {

        u64 n = cols();
        u64 m = rows();
        u64 k = 0;
        u64 i = 0;
        u64 v = n;

        blocks.resize(0);
        

        // temps
        std::vector<View::Idx> colSwaps;


        // We are going to create a 'view' over the matrix.
        // At each iterations we will move some of the rows 
        // and columns in the view to the top/left. These 
        // moved rows will then be excluded from the view.
        // 
        View H(*this);

        std::unique_ptr<LDPC> HH;
        if (verbose)
        {
            HH.reset(new LDPC(*this));
        }

        //std::vector<View::Idx> colIdx(rowWeight());
        //std::vector<u64> dks;
        std::vector<double> avgs(rowWeight() + 1);
        std::vector<u64> max(rowWeight() + 1);
        u64 numSamples(0);

        while (i < m && v)
        {
            numSamples++;
            for (u64 j = 0; j < H.mSmallWeightSets.size(); ++j)
            {
                avgs[j] += H.mSmallWeightSets[j].size();
                max[j] = std::max(max[j], H.mSmallWeightSets[j].size());
            }

            for (u64 j = 0; j < H.mBigWeightSets.size(); ++j)
            {
                auto jj = j + H.mSmallWeightSets.size();
                avgs[jj] += H.mBigWeightSets[j].size();
                max[jj] = std::max(max[jj], H.mBigWeightSets[j].size());
            }

            if (H.mSmallWeightSets[0].size() == 0)
            {
                // If we don't have any rows with hamming
                // weight 0 then we will pick the row with 
                // minimim hamming weight and move it to the
                // top of the view.
                auto uu = H.popMinWeightRow();
                auto u = uu.first;
                auto wi = uu.second;

                // move the min weight row u to row i.
                auto ii = H.rowIdx(i);
                H.swapRows(u, ii);

                if (verbose) {
                    std::cout << "wi " << wi << std::endl;
                    std::cout << "swapRow(" << i << ", " << u.mIdx << ")" << std::endl;
                }

                // For this newly moved row i, we need to move all the 
                // columns where this row has a non-zero value to the
                // left side of the view. 

                // c1 is the column defining the left side of the view
                auto c1 = (n - v);

                // rIter iterates the columns which have non-zero values for row ii.
                auto rIter = H.rowIterator(ii);

                // this set will collect all of the columns in the view. 
                colSwaps.clear();
                for (u64 j = 0; j < rowWeight(); ++j)
                {
                    //auto c0 = colIdx[j];
                    auto c0 = *rIter; ++rIter;

                    // check if this column is inside the view.
                    if (c0.mIdx >= c1)
                    {
                        // add this column to the set of columns that we will move.
                        colSwaps.push_back(c0);

                        if (verbose)
                            std::cout << "swapCol(" << c0.mIdx << ")" << std::endl;

                        // iterator over the rows for this column and decrement their row weight.
                        // we do this since we are about to move this column outside of the view.
                        auto cIter = H.colIterator(c0);
                        while (cIter)
                        {
                            // these a special case that this row is the u row which
                            // has already been decremented
                            if (cIter.srcIdx() != ii.mSrcIdx)
                            {
                                H.decRowWeight(*cIter);
                            }

                            ++cIter;
                        }
                    }
                }

                // now update the mappings so that these columns are
                // right before the view.
                while (colSwaps.size())
                {
                    auto cc = H.colIdx(c1++);
                    auto sIter = std::find(colSwaps.begin(), colSwaps.end(), cc);
                    if (sIter != colSwaps.end())
                    {
                        std::swap(*sIter, colSwaps.back());
                    }
                    else
                    {
                        H.swapCol(cc, colSwaps.back());
                    }

                    colSwaps.pop_back();
                }

                if (verbose)
                {
                    std::cout << "v " << (v - wi) << " = " << v << " - " << wi << std::endl;
                    std::cout << "i " << (i + 1) << " = " << i << " + 1" << std::endl;
                }

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


                auto& rows = H.mSmallWeightSets[0];
                auto dk = rows.size();

                // the top of the view.
                auto c1 = i;

                while (rows.size())
                {
                    // check that there isn't already a row
                    // that we want at the top.
                    auto sIter = std::find(rows.begin(), rows.end(), c1);
                    auto srcIdx = c1;

                    if (sIter == rows.end())
                    {
                        // if not then pick an arbitrary row
                        // that we will move to the top.
                        sIter = rows.begin();

                        auto dest = H.rowIdx(c1);
                        auto src = H.rowSrcIdx(*sIter);
                        srcIdx = src.mIdx;

                        H.swapRows(dest, src);
                    }

                    if (verbose)
                        std::cout << "rowSwap*(" << c1 << ", " << srcIdx << ")" << std::endl;

                    rows.erase(sIter);
                    ++c1;
                }

                // recode that this the end of the block.
                blocks.push_back({ i + dk, n - v, dk});
                //dks.push_back(dk);

                if (verbose)
                {
                    std::cout << "RC " << blocks.back()[0] << " " << blocks.back()[1] << std::endl;
                    std::cout << "i " << (i + dk) << " = " << i << " + " << dk << std::endl;
                    std::cout << "k " << (k + 1) << " = " << k << " + 1" << std::endl;
                }

                i += dk;
                ++k;
            }

            if (verbose)
            {
                auto bb = blocks;
                bb.push_back({ i, n - v });
                auto W = *this;
                H.applyPerm(W);
                
                std::vector<u64> weights(rows());
                for (u64 i = 0; i < weights.size(); ++i)
                    weights[i] = H.mRowWeights[H.mRowNOMap[i]];

                std::cout << "\n" << diff(W.mRows, HH->mRows, bb, &weights) << std::endl
                    << "=========================================\n"
                    << std::endl;

                *HH = std::move(W);
            }
        }

        //R.push_back(m);
        //C.push_back(n);

        rowPerm = H.mRowONMap;
        colPerm = H.mColONMap;

        if(apply)
            H.applyPerm(*this);

        if (stats)
        {

            for (u64 j = 0; j < avgs.size(); ++j)
            {
                std::cout << j << " avg  " << avgs[j] / numSamples << "  max  " << max[j] << std::endl;
            }
            std::array<u64, 3> prev = {};
            for (u64 j = 0; j < blocks.size(); ++j)
            {
                if (j == 50 && blocks.size() > 150)
                {
                    std::cout << "..." << std::endl;
                    j = blocks.size() - 50;
                }


                std::string dk;
                //if (i < dks.size())
                //    dk = std::to_string(dks[i]);

                std::cout << "RC[" << j << "] " << (blocks[j][0] - prev[0]) << " " << (blocks[j][1] - prev[1]) << "  ~   " << dk << std::endl;
                prev = blocks[j];
            }

            if (prev[0] != mRows.rows())
            {
                std::cout << "RC[" << blocks.size() << "] " << (mRows.rows() - prev[0]) << " " << (mNumCols - prev[1]) << "  ~   0" << std::endl;
            }
        }

        //*this = applyPerm(H.mRowONMap, H.mColONMap);
    }

    void LDPC::validate()
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




}