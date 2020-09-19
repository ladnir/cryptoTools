#include "Test.h"
#include "LDPC.h"
#include <iostream>
#include "cryptoTools/Common/TestCollection.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include "cryptoTools/Common/Timer.h"
#include "../cpp-btree/btree/set.h"
#include <random>
#include "FWPC.h"

namespace osuCrypto
{






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





    void blockTriangulateTest2(const CLP& cmd)
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
            std::vector<std::array<u64, 3>> bb;
            std::vector<u64> R, C;

            if (v)
                std::cout << H << std::endl
                << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;

            H.blockTriangulate(bb, R, C, v, false);
            if (isBlockTriangular(H, R, C) == false)
                throw UnitTestFail(LOCATION);
        }
    }


    void unitTest(CLP& cmd)
    {

        oc::TestCollection tests;
        tests.add("blockTriangulateTest2   ", blockTriangulateTest2);



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

        u64 w = cmd.getOr("w", 0);
        u64 d = cmd.getOr("d", 0);
        double exp = cmd.getOr("exp", 0.0);
        std::vector<std::array<u64, 2>> points; points.reserve(m * h);
        Timer timer;

        if (exp)
        {
            std::exponential_distribution<double> expDist(1 / exp);
            std::cout << "exp ";
            for (u64 i = 0; i < 30; ++i)
                std::cout << expDist(prng) << " ";
            std::cout << std::endl;
        }

        double dur1(0), dur2(0);
        std::set<u64> c;
        for (u64 i = 0; i < t; ++i)
        {
            points.clear();
            for (u64 i = 0; i < m; ++i)
            {
                if (w)
                {
                    w = std::min(n, w);
                    auto q = (n + w - 1) / w;

                    auto r = u64(double(i) * q / m);

                    //auto r = prng.get<u64>() % q;

                    auto begin = n * r / q;
                    auto end = n * (r + 1) / q;
                    auto nn = end - begin;

                    while (c.size() != h)
                        c.insert(prng.get<u64>() % nn + begin);

                }
                else if (d)
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
                    std::exponential_distribution<double> expDist(1 / exp);

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


            {
                CuckooIndex<> cuckoo;
                cuckoo.init(m, 40, 0, 3);
                std::vector<block> inputs(m);
                prng.get(inputs.data(), inputs.size());

                auto start = timer.setTimePoint("");
                cuckoo.insert(inputs, 0);
                auto end = timer.setTimePoint("");
                dur1 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            }

            {

                LDPC H2(m, n, h, points);

                //u64 maxCol = 0;
                //for (u64 i = 0; i < n; ++i)
                //    maxCol = std::max<u64>(maxCol, H.mCols[i].mRowIdxs.size());
                //

                if (v)
                {
                    std::cout << "--------------------------------" << std::endl;
                    std::cout << H2 << std::endl;
                    std::cout << "--------------------------------" << std::endl;
                }

                std::vector<std::array<u64, 3>> bb;
                std::vector<u64> R, C;

                auto start = timer.setTimePoint("");
                H2.blockTriangulate(bb, R, C, v, stats);
                auto end = timer.setTimePoint("");
                dur2 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();


                timer.setTimePoint("triangulate");

                if (v)
                {
                    std::cout << diff(H2.mRows, H2.mRows, bb) << std::endl;
                    std::cout << "--------------------------------" << std::endl;
                }
            }
        }
        //std::cout << "max col " << maxCol << " " << std::log2(m) << std::endl;
        std::cout << dur1 / t << " " << dur2 / t << std::endl;
        //H.partition(R, C, v);
        //std::cout << "--------------------------------" << std::endl;
        //std::cout << H << std::endl;

        return;
    }



    void fwpc(CLP& cmd)
    {
        bool v = cmd.isSet("v");
        bool stats = cmd.isSet("stats");

        // The number of constaints
        u64 numRows = cmd.getOr("m", 30ull);
        // The 
        u64 numCols = numRows * cmd.getOr<double>("e", 2.4);
        u64 weight = cmd.getOr("h", 2);
        u64 t = cmd.getOr("t", 1);
        PRNG prng(block(0, cmd.getOr("s", 0)));

        u64 binWidth = cmd.getOr("w", 10);
        binWidth = std::min(numCols, binWidth);

        Matrix<u64> points(numRows, weight);
        Timer timer;

        double dur1(0), dur2(0);
        std::set<u64> c;
        for (u64 i = 0; i < t; ++i)
        {
            for (u64 i = 0; i < numRows; ++i)
            {
                //if (d)
                //{
                //    auto base = prng.get<u64>() % (n-d);
                //    c.insert(base);

                //    while (c.size() != h)
                //        c.insert((base + prng.get<u64>() % d) % n);
                //}
                if (binWidth)
                {
                    auto numBins = (numCols + binWidth - 1) / binWidth;

                    auto binIdx = u64(double(i) * numBins / numRows);

                    //auto r = prng.get<u64>() % q;

                    auto colBegin = (binIdx * numCols) / numBins;
                    auto colEnd = ((binIdx + 1) * numCols) / numBins;
                    auto nn = colEnd - colBegin;

                    while (c.size() != weight)
                        c.insert(prng.get<u64>() % nn + colBegin);

                }

                std::copy(c.begin(), c.end(), points[i].begin());
                c.clear();
            }


            {

                //LDPC H2(m, n, h, points);
                FWPC H;
                H.insert(numCols, binWidth, points);
                auto H2 = H;

                print(std::cout, points, numCols);

                //u64 maxCol = 0;
                //for (u64 i = 0; i < n; ++i)
                //    maxCol = std::max<u64>(maxCol, H.mCols[i].mRowIdxs.size());
                //

                //if (v)
                //{
                    std::cout << "--------------------------------" << std::endl;
                    std::cout << H << std::endl;
                    std::cout << "--------------------------------" << std::endl;
                //}

                std::vector<std::array<u64, 3>> bb;
                std::vector<u64> R, C;            


                //auto start = timer.setTimePoint("");
                H.blockTriangulate(bb, R, C, v, stats);
                //auto end = timer.setTimePoint("");
                //dur2 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();


                //timer.setTimePoint("triangulate");

                if (v)
                {
                    //std::cout << diff(H.mRows, H2.mRows, bb) << std::endl;
                    std::cout << "--------------------------------" << std::endl;
                    std::cout << H << std::endl;
                }
            }
        }
        //std::cout << "max col " << maxCol << " " << std::log2(m) << std::endl;
        //std::cout << dur1 / t << " " << dur2 / t << std::endl;
        //H.partition(R, C, v);
        //std::cout << "--------------------------------" << std::endl;
        //std::cout << H << std::endl;

        return;
    }

}