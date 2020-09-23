#include "Test.h"
#include "LDPC.h"
#include <iostream>
#include "cryptoTools/Common/TestCollection.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include "cryptoTools/Common/Timer.h"
#include "../cpp-btree/btree/set.h"
#include <random>
#include "FWPC.h"
#include "libdivide.h"
namespace osuCrypto
{


    template<typename Size>
    bool isTriangular(MatrixView<Size> H)
    {
        u64 colIdx = 0;
        for (u64 i = 0; i < H.rows(); ++i)
        {
            auto row = H[i];
            auto maxCol = *std::max_element(row.begin(), row.end());
            if (maxCol < colIdx)
                return false;
            colIdx = maxCol;
        }
        return true;
    }


    template<typename Size>
    bool isBlockTriangular(MatrixView<Size> H, Size numCols, std::vector<std::array<Size,3>>& blocks_)
    {
        auto blocks = blocks_;
        if (blocks.size() == 0 || blocks.back()[0] != H.rows())
        {
            blocks.push_back({ Size(H.rows()), Size(numCols), Size(0) });
        }
        auto bb = blocks.begin();
        u64 colIdx = 0;
        for (u64 i = 0; i < H.rows(); ++i)
        {
            auto row = H[i];
            auto maxCol = *std::max_element(row.begin(), row.end());
            auto b = *bb;

            if (b[0] - b[2] <= i)
            {
                if (b[1] != maxCol)
                    return false;
            }

            if (maxCol > b[1])
                return false;

            if (b[0] == i)
            {
                ++bb;
            }

            if (maxCol < colIdx)
                return false;
            colIdx = maxCol;
        }
        return true;
    }


    template<typename Size>
    bool isSame(MatrixView<Size> H, MatrixView<Size> H2, std::vector<Size>& rowPerm, std::vector<Size>& colPerm)
    {
        if (H.rows() != H2.rows() || H.cols() != H2.cols())
            return false;
        //Matrix<Size> H3(H.rows(), H.cols());
        for (u64 i = 0; i < H.rows(); ++i)
        {
            for (u64 j = 0; j < H.cols(); ++j)
            {
                // o to n
                auto newRow = rowPerm[i];
                //auto newCol = colPerm[j];


                if (H(newRow, j) != colPerm[H2(i, j)])
                    return false;
            }
        }
        return true;

    }



    
    template<typename Size>
    void LDPC_blockTriangulateTest(const CLP& cmd)
    {
        bool v = cmd.isSet("v");
        u64 m = cmd.getOr("m", 1000ull);

        u64 n = m * cmd.getOr<double>("e", 2.4);
        u64 h = cmd.getOr("h", 3);

        u64 trials = cmd.getOr("t", 100);
        u64 tt = cmd.getOr("tt", 0);


        Matrix<Size> points(m, h);
        for (; tt < trials; ++tt)
        {
            PRNG prng(block(0, cmd.getOr("s", tt)));

            std::set<u64> c;
            for (u64 i = 0; i < m; ++i)
            {

                while (c.size() != h)
                    c.insert(prng.get<u64>() % n);
                
                auto row = points[i];
                std::copy(c.begin(), c.end(), row.begin());
                c.clear();
            }

            static const int Weight = 3;
            if (h != Weight)
            {
                std::cout << "only h=3 impl" << std::endl;
                throw RTE_LOC;
            }

           
            LDPC<Size, Weight> H(n, points);


            auto HH = H;
            std::vector<std::array<Size, 3>> bb;
            std::vector<Size> R, C;

            if (v)
                std::cout << H << std::endl
                << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;

            H.blockTriangulate(bb, R, C, v, false, true);

            auto vv = view<Size, Weight>(H.mRows);
            if (isBlockTriangular<Size>(vv, n, bb) == false)
            {
                if (v)
                    std::cout << H << std::endl
                    << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;

                throw UnitTestFail(LOCATION);
            }

            if (isSame(vv, points, R, C) == false)
            {
                if (v)
                    std::cout << H << std::endl
                    << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;

                throw UnitTestFail(LOCATION);
            }

        }
    }


    void FWPC_blockTriangulateTest(const CLP& cmd)
    {
        bool v = cmd.isSet("v");
        u64 numRows = cmd.getOr("m", 1000ull);

        u64 numCols = numRows * cmd.getOr<double>("e", 2.4);
        u64 weight = cmd.getOr("h", 2);

        u64 binWidth = cmd.getOr("w", 100);
        binWidth = std::min(binWidth, numCols);

        u64 trials = cmd.getOr("t", 100);
        u64 tt = cmd.getOr("tt", 0);


        Matrix<u64> points(numRows, weight);
        for (; tt < trials; ++tt)
        {
            PRNG prng(block(0, cmd.getOr("s", tt)));

            std::set<u64> c;
            //for (u64 i = 0; i < numRows; ++i)
            //{

            //    while (c.size() != h)
            //        c.insert(prng.get<u64>() % numCols);

            //    auto row = points[i];
            //    std::copy(c.begin(), c.end(), row.begin());
            //    c.clear();
            //}
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

            FWPC H(numCols, binWidth, points);


            auto HH = H;
            std::vector<std::array<u64, 3>> bb;
            std::vector<u64> R, C;

            if (v)
                std::cout << H << std::endl
                << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;

            H.blockTriangulate(bb, R, C, v, false);
            if (isBlockTriangular(H.mRows, numCols, bb) == false)
                throw UnitTestFail(LOCATION);
            if (isSame(H.mRows, points, R, C) == false)
                throw UnitTestFail(LOCATION);
        }
    }


    void unitTest(CLP& cmd)
    {

        oc::TestCollection tests;
        tests.add("LDPC.blockTriangulateTest16 ", LDPC_blockTriangulateTest<u16>);
        tests.add("LDPC.blockTriangulateTest64 ", LDPC_blockTriangulateTest<u64>);
        tests.add("FWPC.blockTriangulateTest   ", FWPC_blockTriangulateTest);



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


    void ldpcMain(CLP& cmd)
    {
        if (cmd.isSet("u"))
            return unitTest(cmd);

        if(cmd.isSet("w"))
            fwpc(cmd);
        else
            ldpc(cmd);

    }

    void ldpc(CLP& cmd)
    {

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
        Matrix<u64>points(m,h);
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

                std::copy(c.begin(), c.end(), points[i].begin());

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

            if(h == 2)
            {

                LDPC<u64, 2> H2(n, points);

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
                H2.blockTriangulate(bb, R, C, v, stats, false);
                auto end = timer.setTimePoint("");
                dur2 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();


                timer.setTimePoint("triangulate");

                if (v)
                {
                    std::cout << diff(H2.mRows, H2.mRows, bb, H2.cols()) << std::endl;
                    std::cout << "--------------------------------" << std::endl;
                }
            }
            else if (h == 3)
            {

                LDPC<u64, 3> H2(n, points);
                if (v)
                {
                    std::cout << "--------------------------------" << std::endl;
                    std::cout << H2 << std::endl;
                    std::cout << "--------------------------------" << std::endl;
                }

                std::vector<std::array<u64, 3>> bb;
                std::vector<u64> R, C;

                auto start = timer.setTimePoint("");
                H2.blockTriangulate(bb, R, C, v, stats, false);
                auto end = timer.setTimePoint("");
                dur2 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();


                timer.setTimePoint("triangulate");

                if (v)
                {
                    std::cout << diff(H2.mRows, H2.mRows, bb, H2.cols()) << std::endl;
                    std::cout << "--------------------------------" << std::endl;
                }
            }
            else
            {
                std::cout << "h not implemented" << std::endl;
                throw RTE_LOC;
            }
        }
        //std::cout << "max col " << maxCol << " " << std::log2(m) << std::endl;
        std::cout << dur1 / t << " " << dur2 / t << std::endl;
        //H.partition(R, C, v);
        //std::cout << "--------------------------------" << std::endl;
        //std::cout << H << std::endl;

        return;
    }

    template<typename Size> 
    void fill(std::vector<u64>& c, u64 w, u64 nn, u64 colBegin, PRNG& prng)
    {
        while (c.size() != w)
        {
            auto col = prng.get<Size>() % nn + colBegin;
            auto iter = std::find(c.begin(), c.end(), col);
            if (iter == c.end())
            {
                c.push_back(col);
            }
        }
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
        auto numBins = (numCols + binWidth - 1) / binWidth;

        Matrix<u64> points(numRows, weight);
        Timer timer;

        libdivide::divider<u64> numRowsDiv(numRows);
        libdivide::divider<u64> numBinsDiv(numBins);

        double dur1(0), dur2(0);
        std::vector<u64> c;
        for (u64 i = 0; i < numRows; ++i)
        {
            auto binIdx = i * numBins / numRowsDiv;
            auto colBegin = (binIdx * numCols) / numBinsDiv;
            auto colEnd = ((binIdx + 1) * numCols) / numBinsDiv;
            auto nn = colEnd - colBegin;
            if (nn < std::numeric_limits<u16>::max())
            {
                fill<u16>(c, weight, nn, colBegin, prng);
            }
            else if (nn < std::numeric_limits<u32>::max())
            {
                fill<u32>(c, weight, nn, colBegin, prng);
            }
            else
            {
                fill<u64>(c, weight, nn, colBegin, prng);
            }

            memcpy(&points(i, 0), c.data(), sizeof(u64) * weight);
            c.clear();
        }


        for (u64 i = 0; i < t; ++i)
        {


            if(cmd.isSet("cuckoo"))
            {
                CuckooIndex<> cuckoo;
                cuckoo.init(numRows, 40, 0, 3);
                std::vector<block> inputs(numRows);
                prng.get(inputs.data(), inputs.size());

                auto start = timer.setTimePoint("");
                cuckoo.insert(inputs, 0);
                auto end = timer.setTimePoint("");
                dur1 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            }

            {

                //LDPC H2(m, n, h, points);
                FWPC H;
                H.insert(numCols, binWidth, points);
                auto H2 = H;

                //print(std::cout, points, numCols);

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

                std::vector<std::array<u64, 3>> bb;
                std::vector<u64> R, C;            


                auto start = timer.setTimePoint("");
                H.blockTriangulate(bb, R, C, v, stats);
                auto end = timer.setTimePoint("");
                dur2 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();


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
        std::cout << dur1 / t << " " << dur2 / t << std::endl;
        //H.partition(R, C, v);
        //std::cout << "--------------------------------" << std::endl;
        //std::cout << H << std::endl;

        return;
    }

}