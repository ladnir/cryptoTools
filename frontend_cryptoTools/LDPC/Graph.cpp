#include "Graph.h"
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/TestCollection.h>
#include <random>
#include <numeric>
//#include "sparsehash/dense_hash_set"
//#include "sparsehash/sparse_hash_set"

#include "../flat_hash_map/bytell_hash_map.hpp"
#include "../hopscotch-map/include/tsl/bhopscotch_set.h"
#include "../hopscotch-map/include/tsl/hopscotch_set.h"
#include "../ordered-map/include/tsl/ordered_set.h"
#include "../sparse-map/include/tsl/sparse_set.h"
#include "../robin-map/include/tsl/robin_set.h"
#include "../cpp-btree/btree/set.h"
//#include "absl/container/btree_set.h"
//#include "absl/container/flat_hash_set.h"
//#include "absl/container/node_hash_set.h"

namespace osuCrypto
{


    std::ostream& operator<<(std::ostream& o, const LDPC& s)
    {
        for (u64 i = 0; i < s.mRows.rows(); ++i)
        {
            std::unordered_set<u64> c;
            for (u64 j = 0; j < s.mRows.cols(); j++)
                c.insert(s.mRows(i, j));

            for (u64 j = 0; j < s.cols(); ++j)
            {
                if (c.find(j) != c.end())
                {
                    o << "1 ";
                }
                else
                {
                    o << "0 ";
                }
            }
            o << "\n";
        }

        o << "\n";
        //for (u64 w = 0; w < s.mCols.size(); ++w)
        //    o << s.mCols[w].mRowIdxs.size() << " ";
        //o << "\n";


        return o;
    }



    std::ostream& operator<<(std::ostream& o, const LDPC::diff& s)
    {
        std::array<oc::Color, 2> colors{ oc::Color::Blue, oc::Color::Green };
        u8 rowColorIdx = 0;
        for (u64 i = 0; i < s.mL.mRows.rows(); ++i)
        {

            std::unordered_set<u64> lc, rc;
            for (u64 j = 0; j < s.mL.mRows.cols(); j++)
                lc.insert(s.mL.mRows(i, j));
            for (u64 j = 0; j < s.mR.mRows.cols(); j++)
                rc.insert(s.mR.mRows(i, j));

            auto diffCols = lc;
            for (auto c : rc)
            {
                auto iter = diffCols.find(c);
                if (iter == diffCols.end())
                    diffCols.insert(c);
                else
                    diffCols.erase(iter);
            }

            if (std::find(s.mRIdx.begin(), s.mRIdx.end(), i) != s.mRIdx.end())
            {
                rowColorIdx ^= 1;
            }

            auto colorIdx = rowColorIdx;
            for (u64 j = 0; j < s.mL.cols(); ++j)
            {

                if (std::find(s.mCIdx.begin(), s.mCIdx.end(), j) != s.mCIdx.end())
                {
                    colorIdx ^= 1;
                }


                if (diffCols.find(j) != diffCols.end())
                    o << oc::Color::Red;
                else
                    o << colors[colorIdx];

                if (lc.find(j) != lc.end())
                {
                    o << "1 ";
                }
                else
                {
                    o << "0 ";
                }
                o << oc::Color::Default;
            }
            o << "\n";
        }

        //o << "\n";
        //for (u64 w = 0; w < s.mL.cols(); ++w)
        //    o << s.mL.mCols[w].mRowIdxs.size() << " ";
        //o << "\n";


        return o;
    }

    //bool isSame(LDPC& L, LDPC& R)
    //{
    //    std::vector<u64> rMap(R.cols());
    //    for (u64 i = 0; i < R.cols(); ++i)
    //        rMap[R.mColSrcIdx[i]] = i;

    //    for (u64 i = 0; i < L.cols(); ++i)
    //    {
    //        auto& lCol = L.col(i);
    //        auto& rCol = R.col(rMap[L.mColSrcIdx[i]]);

    //        std::unordered_set<u64> lRows, rRows;

    //        for (u64 j = 0; j < lCol.size(); j++)
    //            lRows.insert(L.mRowSrcIdx[lCol[j]]);
    //        for (u64 j = 0; j < rCol.size(); j++)
    //            rRows.insert(R.mRowSrcIdx[rCol[j]]);

    //        if (lRows != rRows)
    //            return false;
    //    }

    //    return true;
    //}

    bool isBlockTriangular(LDPC& H, std::vector<u64>& R, std::vector<u64>& C)
    {
        u64 curRowIdx = 0;
        for (u64 i = 0; i < H.cols(); ++i)
        {
            auto col = H.col(i);
            auto iter = std::min_element(col.begin(), col.end());
            u64 m = iter == col.end() ? ~0ull : *iter;
            if (m < curRowIdx)
            {
                std::cout << H << std::endl;
                return false;
            }

            curRowIdx = m;
        }

        for (u64 i = 0; i < C.size() - 1; ++i)
        {
            auto cBegin = C[i];
            auto cEnd = C[i + 1];
            auto minRowIdx = R[i];

            for (u64 j = cBegin; j < cEnd; ++j)
            {
                auto& col = H.col(j);
                auto iter = std::min_element(col.begin(), col.end());
                if (iter != col.end() && *iter < minRowIdx)
                {
                    return false;
                }
            }
        }

        return true;
    }

    void blockTriangulateTest(const CLP& cmd)
    {
        bool v = cmd.isSet("v");
        u64 m = cmd.getOr("m", 40ull);

        u64 n = m * cmd.getOr<double>("e", 2.4);
        u64 h = cmd.getOr("h", 2);

        u64 trials = cmd.getOr("t", 100);
        u64 tt = cmd.getOr("tt", 0);


        std::vector<std::array<u64, 2>> points; points.reserve(m * h);
        for (; tt < trials; ++tt)
        {
            PRNG prng(block(0, cmd.getOr("s", tt)));

            points.clear();
            std::set<u64> c;
            for (u64 i = 0; i < m; ++i)
            {

                while (c.size() != h)
                    c.insert(prng.get<u64>() % n);
                for (auto cc : c)
                    points.push_back({ i, cc });

                c.clear();
            }

            LDPC H(m, n, h, points);


            auto HH = H;
            std::vector<u64> R, C;

            if (v)
                std::cout << H << std::endl
                << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;

            H.blockTriangulate2(R, C, v, false);

            //if (isSame(H, HH) == false)
            //    throw UnitTestFail(LOCATION);

            if (isBlockTriangular(H, R, C) == false)
                throw UnitTestFail(LOCATION);
        }
    }


    void unitTest(CLP& cmd)
    {

        oc::TestCollection tests;
        tests.add("blockTriangulateTest    ", blockTriangulateTest);



        tests.runIf(cmd);
    }

    template<typename Set>
    void doBench(u64 n, Timer& timer, std::string tag, Set& set)
    {
        timer.setTimePoint(tag + ".setup");

        for (u64 i = 0; i < n; ++i)
        {
            set.insert(i);
        }
        timer.setTimePoint(tag + ".insert");

        for (u64 i = 1; i < n; i += 2)
        {
            auto iter = set.find(i);
            if (iter == set.end())
                throw RTE_LOC;
        }
        timer.setTimePoint(tag + ".find");

        for (u64 i = 0; i < n; i += 2)
        {
            auto iter = set.find(i);
            set.erase(iter);
        }
        timer.setTimePoint(tag + ".find_erase");

        while (set.size())
        {
            set.erase(set.begin());

            //if (set.load_factor() < shink)
            //    set.resize(set.size());
        }

        timer.setTimePoint(tag + ".begin_erase");

    }


    void hashBench(CLP& cmd)
    {

        u64 n = cmd.getOr("n", 100000);

        float shink(0.2);
        float grow(0.9);


        Timer timer;
        timer.setTimePoint("");
        {
            std::unordered_set<u64> set;
            set.reserve(n);
            doBench(n, timer, "std::unordered", set);
        }
        {
            std::set<u64> set;
            doBench(n, timer, "  std::ordered", set);
        }
        //{
        //    ska::bytell_hash_set<u64> set;
        //    set.reserve(n);
        //    doBench(n, timer, "   ska::bytell", set);
        //}
        //{
        //    ska::flat_hash_set<u64> set;
        //    set.reserve(n);
        //    doBench(n, timer, "     ska::flat", set);
        //}

        {

            btree::set<u64> set;
            doBench(n, timer, "btree         ", set);
        }
        //{
        //    
        //    absl::node_hash_set<u64>set;
        //    set.reserve(n);
        //    //set.set_deleted_key(~1ull);
        //    //set.set_resizing_parameters(0.2, 0.9);
        //    doBench(n, timer, "absl::node_set", set);

        //}

        //{

        //    absl::flat_hash_set<u64> set;
        //    set.reserve(n);
        //    //set.set_empty_key(~0ull);
        //    //set.set_deleted_key(~1ull);
        //    //set.set_resizing_parameters(0.2, 0.9);
        //    doBench(n, timer, "absl::flat_set", set);
        //}
        //{
        //    tsl::bhopscotch_set<u64> set;
        //    set.reserve(n);
        //    doBench(n, timer, "bhopscotch   ", set);
        //}
        //{
        //    tsl::hopscotch_set<u64> set;
        //    set.reserve(n);
        //    doBench(n, timer, "hopscotch    ", set);
        //}

        //{
        //    tsl::ordered_set<u64> set;
        //    set.reserve(n);
        //    doBench(n, timer, "ordered_set  ", set);
        //}
        //{
        //    tsl::sparse_set<u64> set;
        //    set.reserve(n);
        //    doBench(n, timer, "sparse_set  ", set);
        //}
        //{
        //    tsl::robin_set<u64> set;
        //    set.reserve(n);
        //    doBench(n, timer, "robin_set   ", set);
        //}

        std::cout << timer << std::endl;

    }
    //         n
    //    xxxxxxxxxxxx   x    y
    // m  xxxx H xxxxx * x =  y
    //    xxxxxxxxxxxx   x    y
    //                   x
    //                   x
    //                   x
    //
    void ldpc(CLP& cmd)
    {
        if (cmd.isSet("hash"))
            return hashBench(cmd);
        if (cmd.isSet("u"))
            return unitTest(cmd);

        bool v = cmd.isSet("v");
        bool stats = cmd.isSet("stats");

        // The number of constaints
        u64 m = cmd.getOr("m", 30ull);
        // The 
        u64 n = m * cmd.getOr<double>("e", 2.4);
        u64 h = cmd.getOr("h", 2);
        u64 t = cmd.getOr("t", 1);
        PRNG prng(block(0, cmd.getOr("s", 0)));

        u64 d = cmd.getOr("d", 0);
        double exp = cmd.getOr("exp", 0.0);
        std::vector<std::array<u64, 2>> points; points.reserve(m * h);
        Timer timer;

        double dur(0);
        std::set<u64> c;
        for (u64 i = 0; i < t; ++i)
        {
            points.clear();
            for (u64 i = 0; i < m; ++i)
            {
                if (d)
                {
                    auto base = prng.get<u64>() % n;
                    c.insert(base);

                    while (c.size() != h)
                        c.insert((base + prng.get<u64>() % d) % n);
                }
                else if (exp)
                {

                    auto base = prng.get<u64>() % n;
                    c.insert(base);
                    std::exponential_distribution<double> expDist(exp);

                    while (c.size() != h)
                        c.insert(u64(base + expDist(prng)) % n);
                }
                else
                {
                    while (c.size() != h)
                        c.insert(prng.get<u64>() % n);
                }

                for (auto cc : c)
                    points.push_back({ i, cc });

                c.clear();
            }


            LDPC H(m, n, h, points);

            //u64 maxCol = 0;
            //for (u64 i = 0; i < n; ++i)
            //    maxCol = std::max<u64>(maxCol, H.mCols[i].mRowIdxs.size());
            //

            if (v)
            {
                std::cout << "--------------------------------" << std::endl;
                std::cout << H << std::endl;
                std::cout << "--------------------------------" << std::endl;
            }

            std::vector<u64> R, C;

            auto start = timer.setTimePoint("");
            H.blockTriangulate2(R, C, v, stats);
            auto end = timer.setTimePoint("");
            dur += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();


            timer.setTimePoint("triangulate");

            if (v)
            {
                std::cout << LDPC::diff(H, H, R, C) << std::endl;
                std::cout << "--------------------------------" << std::endl;
            }
        }
        //std::cout << "max col " << maxCol << " " << std::log2(m) << std::endl;
        std::cout << dur / t << std::endl;
        //H.partition(R, C, v);
        //std::cout << "--------------------------------" << std::endl;
        //std::cout << H << std::endl;

        return;
    }

    //void LDPC::reset(u64 rows, u64 cols, u64 rowWeight)
    //{

    //}
    void LDPC::insert(u64 rows, u64 cols, u64 rowWeight, std::vector<std::array<u64, 2>>& points)
    {
        if (rows * rowWeight != points.size())
            throw RTE_LOC;

        mNumCols = cols;
        mRows.resize(0, 0);
        //mCols.clear();
        mColData.clear();
        mRows.resize(rows, rowWeight);
        memset(mRows.data(), -1, mRows.size() * sizeof(u64));

        mColData.resize(rows * rowWeight);
        memset(mColData.data(), -1, mColData.size() * sizeof(u64));

        mColStartIdxs.resize(cols + 1);

        //mRowSrcIdx.resize(rows);
        //mColSrcIdx.resize(cols);
        //std::iota(mRowSrcIdx.begin(), mRowSrcIdx.end(), 0);
        //std::iota(mColSrcIdx.begin(), mColSrcIdx.end(), 0);


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

    void LDPC::moveRows(u64 destIter, std::unordered_set<u64> srcRows)
    {
        while (srcRows.size())
        {
            auto sIter = srcRows.find(destIter);
            if (sIter == srcRows.end())
            {
                swapRow(destIter, *srcRows.begin());
                srcRows.erase(srcRows.begin());
            }
            else
                srcRows.erase(sIter);
            ++destIter;
        }
    }
    void LDPC::swapRow(u64 r0, u64 r1)
    {
        if (r0 == r1)
            return;

        auto rr0 = mRows[r0];
        auto rr1 = mRows[r1];

        for (u64 i = 0; i < rr0.size(); ++i)
        {
            *std::find(col(rr0[i]).begin(), col(rr0[i]).end(), r0) = r1;
            *std::find(col(rr1[i]).begin(), col(rr1[i]).end(), r1) = r0;
        }

        std::swap_ranges(rr0.begin(), rr0.end(), rr1.begin());
        //std::swap(mRowSrcIdx[r0], mRowSrcIdx[r1]);
    }
    void LDPC::moveCols(u64 destIter, std::unordered_set<u64> srcCols)
    {
        while (srcCols.size())
        {
            auto sIter = srcCols.find(destIter);
            if (sIter == srcCols.end())
            {
                swapCol(destIter, *srcCols.begin());
                srcCols.erase(srcCols.begin());
            }
            else
                srcCols.erase(sIter);

            ++destIter;
        }
    }
    void LDPC::swapCol(u64 c0, u64 c1)
    {
        if (c0 == c1)
            return;

        auto cc0 = col(c0);
        auto cc1 = col(c1);

        for (auto rIdx : cc0)
        {
            auto row = mRows[rIdx];
            *std::find(row.begin(), row.end(), c0) = c1;
            std::sort(row.begin(), row.end());
        }
        for (auto rIdx : cc1)
        {
            auto row = mRows[rIdx];
            *std::find(row.begin(), row.end(), c1) = c0;
            std::sort(row.begin(), row.end());
        }

        std::swap(cc0, cc1);
    }


    void LDPC::blockTriangulate(std::vector<u64>& R, std::vector<u64>& C, bool verbose)
    {
        u64 n = cols();
        u64 m = rows();
        u64 k = 0;
        u64 i = 0;
        u64 v = n;

        R.resize(0);
        C.resize(0);
        //u64 RSum = 0;
        //u64 CSum = 0;

        std::unordered_set<u64> rowSwaps, colSwaps;

        while (i < m && v)
        {
            auto cBegin = n - v;
            u64 uStar = i;
            u64 wi = HamV(i, cBegin);
            auto HH = *this;


            for (u64 j = i + 1; j < m && wi; ++j)
            {
                u64 wj = HamV(j, cBegin);
                if (wj < wi)
                {
                    wi = wj;
                    uStar = j;
                }
            }

            if (verbose)
            {

                std::cout << "wi " << wi << ", u " << uStar << std::endl;
                std::cout << "swapRow(" << i << ", " << uStar << ");" << std::endl;
            }

            if (wi)
            {
                swapRow(i, uStar);
                colSwaps.clear();

                auto& row = mRows[i];
                auto c1 = n - v;

                for (u64 j = 0; j < mRows.cols(); ++j)
                {
                    auto c0 = row[j];
                    if (c0 >= c1)
                    {
                        colSwaps.insert(c0);
                        if (verbose)
                            std::cout << "swapCol(" << c0 << ");" << std::endl;
                    }
                    //auto c0 = rIter[w];
                    //{
                    //    swapCol(c0, c1);
                    //    ++c1;
                    //}
                }

                moveCols(c1, colSwaps);

                if (verbose)
                {
                    std::cout << "v " << (v - wi) << " = " << v << " - " << wi << std::endl;
                    std::cout << "i " << (i + 1) << " = " << i << " + 1" << std::endl;
                }

                v = v - wi;
                ++i;
            }
            else
            {
                rowSwaps.clear();
                rowSwaps.insert(uStar);
                u64 dk = 1;
                for (u64 j = uStar + 1, ii = i + 1; j < m; ++j)
                {
                    u64 wj = HamV(j, cBegin);
                    if (wj == 0)
                    {
                        if (verbose)
                            std::cout << "swapRow(" << (ii + 1) << ", " << j << ");" << std::endl;
                        rowSwaps.insert(j);

                        ++dk;
                    }
                }

                moveRows(i, rowSwaps);

                R.push_back(i + dk);
                C.push_back(n - v);


                if (verbose)
                {
                    std::cout << "RC " << R.back() << " " << C.back() << std::endl;
                    std::cout << "i " << (i + dk) << " = " << i << " + " << dk << std::endl;
                    std::cout << "k " << (i + 1) << " = " << k << " + 1" << std::endl;
                }

                i += dk;
                ++k;


            }

            auto RR = R; RR.push_back(i);
            auto CC = C; CC.push_back(n - v);
            if (verbose)
                std::cout << "\n" << LDPC::diff(*this, HH, RR, CC) << std::endl
                << "=========================================\n"
                << std::endl;
        }

        R.push_back(m);
        C.push_back(n);
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

#define SKA 0
#define BTR 1
#define STD 2
#define CUR BTR 

#if CUR == STD
        std::vector<std::unordered_set<u64>> mWeightSets;
#elif CUR == SKA
        std::vector<ska::bytell_hash_set<u64>> mWeightSets;
#elif CUR == BTR 
        std::array<std::vector<u64>, 2> mSmallWeightSets;
        std::vector<btree::set<u64>> mBigWeightSets;
#else
        static_assert(0, "");
#endif   


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
#if CUR != BTR
            mWeightSets.back().reserve(b.rows());
#endif
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
                    mRowWeights[idx.mSrcIdx] = -1;
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
                    mRowWeights[idx.mSrcIdx] = -1;
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

        void applyPerm()
        {
            Matrix<u64> newRows(mH.rows(), mH.rowWeight());
            for (u64 i = 0; i < mH.mRows.rows(); i++)
            {
                for (u64 j = 0; j < mH.mRows.cols(); ++j)
                {
                    newRows(mRowONMap[i], j) = mColONMap[mH.mRows(i, j)];
                }
            }
            mH.mRows = std::move(newRows);

            std::vector<u64> newCols(mH.mColData.size());
            std::vector<u64> colStartIdxs(mH.cols() + 1);
            for (u64 i = 0, c = 0; i < mH.cols(); ++i)
            {
                auto oIdx = mColNOMap[i];
                auto b = mH.mColStartIdxs[oIdx];
                auto e = mH.mColStartIdxs[oIdx + 1];
                colStartIdxs[i + 1] = colStartIdxs[i] + (e - b);

                while (b < e)
                {
                    newCols[c++] = mRowONMap[mH.mColData[b++]];
                }
            }
            mH.mColStartIdxs = std::move(colStartIdxs);
            mH.mColData = std::move(newCols);


            //for (u64 i =0; i < mH.cols(); ++i)
            //{
            //    auto col = mH.col(i);
            //    auto newColIdx = mColONMap[i];
            //    
            //    for (auto r : col)
            //    {
            //        newCols[colStartIdxs[newColIdx]++] = mRowONMap[r];
            //    }
            //}


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

    void LDPC::blockTriangulate2(std::vector<u64>& R, std::vector<u64>& C, bool verbose, bool stats)
    {

        u64 n = cols();
        u64 m = rows();
        u64 k = 0;
        u64 i = 0;
        u64 v = n;

        R.resize(0);
        C.resize(0);

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
        std::vector<u64> dks;
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
                //for (u64 j = 0; j < rowWeight(); ++j)
                //{
                //    colIdx[j].mSrcIdx = rIter.mRow[j];
                //    colIdx[j].mIdx = H.mColONMap[colIdx[j].mSrcIdx];
                //}


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
                                //auto idx = *cIter;
                                //auto w = H.mRowWeights[idx.mSrcIdx]--;

                                //auto iter = H.mWeightSets[w].find(idx.mSrcIdx);
                                //H.mWeightSets[w].erase(iter);

                                //H.mWeightSets[w - 1].insert(idx.mSrcIdx);
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

                    // decrement the row weight to -1 to 
                    // denote that its outside the view.
                    --H.mRowWeights[*sIter];
                    if (H.mRowWeights[*sIter] != ~0ull)
                        throw RTE_LOC;

                    if (verbose)
                        std::cout << "rowSwap*(" << c1 << ", " << srcIdx << ")" << std::endl;

                    rows.erase(sIter);
                    ++c1;
                }

                // recode that this the end of the block.
                R.push_back(i + dk);
                C.push_back(n - v);
                dks.push_back(dk);

                if (verbose)
                {
                    std::cout << "RC " << R.back() << " " << C.back() << std::endl;
                    std::cout << "i " << (i + dk) << " = " << i << " + " << dk << std::endl;
                    std::cout << "k " << (k + 1) << " = " << k << " + 1" << std::endl;
                }

                i += dk;
                ++k;
            }

            if (verbose)
            {

                auto RR = R; RR.push_back(i);
                auto CC = C; CC.push_back(n - v);
                auto W = applyPerm(H.mRowONMap, H.mColONMap);

                std::cout << "\n" << LDPC::diff(W, *HH, RR, CC) << std::endl
                    << "=========================================\n"
                    << std::endl;

                *HH = std::move(W);
            }
        }

        R.push_back(m);
        C.push_back(n);


        H.applyPerm();

        if (stats)
        {

            for (u64 j = 0; j < avgs.size(); ++j)
            {
                std::cout << j << " avg  " << avgs[j] / numSamples << "  max  " << max[j] << std::endl;
            }
            u64 rPrev = 0;
            u64 cPrev = 0;
            for (u64 i = 0; i < R.size(); ++i)
            {
                std::string dk;
                if (i < dks.size())
                    dk = std::to_string(dks[i]);

                std::cout << "RC[" << i << "] " << (R[i] - rPrev) << " " << (C[i] - cPrev) << "  ~   " << dk << std::endl;
                rPrev = R[i];
                cPrev = C[i];
            }
        }

        //*this = applyPerm(H.mRowONMap, H.mColONMap);
    }

    void LDPC::partition(const std::vector<u64>& R, const std::vector<u64>& C, bool v)
    {
        //std::array<u64, 2> mins;

        //auto col0 = mCols[0].mRowIdxs;
        //mins[1] = *std::min_element(col0.begin(), col0.end());

        //std::vector<u64> CC;
        //u64 cIdx = 1;
        //for (; cIdx < cols(); ++cIdx)
        //{
        //    mins[0] = mins[1];
        //    auto col = mCols[cIdx].mRowIdxs;
        //    if (col.size() == 0)
        //    {
        //        break;
        //    }

        //    mins[1] = *std::min_element(col.begin(), col.end());

        //    if (mins[0] < mins[1])
        //    {
        //        CC.push_back(cIdx - 1);
        //    }
        //}
        //CC.push_back(cIdx - 1);


        //if (v)
        //{

        //    std::cout << *this << std::endl;
        //    auto iter = CC.begin();
        //    for (u64 i = 0; i < cols(); i++)
        //    {
        //        if (iter != CC.end() && *iter == i)
        //        {
        //            std::cout << "* ";
        //            ++iter;
        //        }
        //        else
        //            std::cout << "  ";
        //    }
        //}
        //return;
    }
    LDPC LDPC::applyPerm(std::vector<u64>& R, std::vector<u64>& C)
    {
        std::vector < std::array<u64, 2>> points; points.reserve(rows() * rowWeight());
        for (u64 i = 0; i < rows(); ++i)
        {
            for (u64 j = 0; j < mRows.cols(); ++j)
                points.push_back({ R[i], C[mRows[i][j]] });
        }
        LDPC H(rows(), cols(), mRows.cols(), points);
        //H.mRowSrcIdx.resize(rows());
        //H.mColSrcIdx.resize(cols());

        //for (u64 i = 0; i < rows(); ++i)
        //    H.mRowSrcIdx[R[i]] = mRowSrcIdx.size() ? mRowSrcIdx[i] : i;
        //for (u64 i = 0; i < cols(); ++i)
        //    H.mColSrcIdx[C[i]] = mColSrcIdx.size() ? mColSrcIdx[i] : i;

        return H;
    }
}