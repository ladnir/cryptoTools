#include "Test.h"
#include "LdpcEncoder.h"
//#include "Test.h"
//#include "LDPC.h"
//#include <iostream>
//#include "cryptoTools/Common/TestCollection.h"
//#include "cryptoTools/Common/CuckooIndex.h"
//#include "cryptoTools/Common/Timer.h"
////#include "../cpp-btree/btree/set.h"
//#include <random>
//#include "FWPC.h"
//#include "libdivide.h"
//namespace osuCrypto
//{
//
//
//    template<typename Size>
//    bool isTriangular(MatrixView<Size> H)
//    {
//        u64 colIdx = 0;
//        for (u64 i = 0; i < H.rows(); ++i)
//        {
//            auto row = H[i];
//            auto maxCol = *std::max_element(row.begin(), row.end());
//            if (maxCol < colIdx)
//                return false;
//            colIdx = maxCol;
//        }
//        return true;
//    }
//
//
//    template<typename Size>
//    bool isBlockTriangular(MatrixView<Size> H, Size numCols, std::vector<std::array<Size,3>>& blocks_)
//    {
//        auto blocks = blocks_;
//        if (blocks.size() == 0 || blocks.back()[0] != H.rows())
//        {
//            blocks.push_back({ Size(H.rows()), Size(numCols), Size(0) });
//        }
//        auto bb = blocks.begin();
//        u64 colIdx = 0;
//        for (u64 i = 0; i < H.rows(); ++i)
//        {
//            auto row = H[i];
//            auto maxCol = *std::max_element(row.begin(), row.end());
//            auto b = *bb;
//
//            auto digRowEnd = b[0] - b[2];
//            auto blkRowNnd = b[0];
//
//            if (i >= digRowEnd)
//            {
//                if (b[1] != maxCol + 1)
//                    return false;
//            }
//
//            if (maxCol > b[1])
//                return false;
//
//            if (b[0] == i + 1)
//            {
//                ++bb;
//            }
//
//            if (maxCol < colIdx)
//                return false;
//            colIdx = maxCol;
//        }
//        return true;
//    }
//
//
//    template<typename Size>
//    bool isSame(MatrixView<Size> H, MatrixView<Size> H2, std::vector<Size>& rowPerm, std::vector<Size>& colPerm)
//    {
//        if (H.rows() != H2.rows() || H.cols() != H2.cols())
//            return false;
//        //Matrix<Size> H3(H.rows(), H.cols());
//        for (u64 i = 0; i < H.rows(); ++i)
//        {
//            for (u64 j = 0; j < H.cols(); ++j)
//            {
//                // o to n
//                auto newRow = rowPerm[i];
//                //auto newCol = colPerm[j];
//                auto col = H2(i, j);
//                auto newCol = colPerm[(col)];
//
//                auto col2 = H(newRow, j);
//
//                if (col2 != newCol)
//                    return false;
//            }
//        }
//        return true;
//
//    }
//
//
//
//    
//    template<typename Size>
//    void LDPC_blockTriangulateTest(const CLP& cmd)
//    {
//        bool v = cmd.isSet("v");
//        u64 m = cmd.getOr("m", 1000ull);
//
//        auto e = cmd.getOr<double>("e", 2.4);
//        u64 n = m * e;
//        u64 h = cmd.getOr("h", 3);
//
//        u64 trials = cmd.getOr("t", 100);
//        u64 tt = cmd.getOr("tt", 0);
//
//        if (n > std::numeric_limits<Size>::max() / 2)
//        {
//            n = std::numeric_limits<Size>::max() / 2;
//            m = n / e;
//        }
//
//        Matrix<Size> points(m, h);
//        for (; tt < trials; ++tt)
//        {
//            PRNG prng(block(0, cmd.getOr("s", tt)));
//
//            std::set<u64> c;
//            for (u64 i = 0; i < m; ++i)
//            {
//
//                while (c.size() != h)
//                    c.insert(prng.get<u64>() % n);
//                
//                auto row = points[i];
//                std::copy(c.begin(), c.end(), row.begin());
//                c.clear();
//            }
//
//            static const int Weight = 3;
//            if (h != Weight)
//            {
//                std::cout << "only h=3 impl" << std::endl;
//                throw RTE_LOC;
//            }
//
//            auto src = points;
//            LDPC<Size, Weight> H(n, points);
//
//
//            auto HH = H;
//            std::vector<std::array<Size, 3>> bb;
//            std::vector<Size> R, C;
//
//            if (v)
//                std::cout << H << std::endl
//                << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;
//
//            H.blockTriangulate(bb, R, C, v, false, true);
//
//            //std::cout << H << std::endl
//            //    << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;
//            //for (auto b : bb)
//            //{
//            //    std::cout << b[0] << " " << b[1] << " " << b[2] << std::endl;
//            //}
//
//            auto vv = view<Size, Weight>(H.mRows);
//            if (isBlockTriangular<Size>(vv, n, bb) == false)
//            {
//                //if (v)
//                std::cout << H << std::endl
//                    << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;
//                for (auto b : bb)
//                {
//                    std::cout << b[0] << " " << b[1] << " " << b[2] << std::endl;
//                }
//                throw UnitTestFail(LOCATION);
//            }
//
//            if (isSame(vv, src, R, C) == false)
//            {
//                //if (v)
//                std::cout << H << std::endl
//                    << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;
//
//                throw UnitTestFail(LOCATION);
//            }
//
//        }
//    }
//
//
//    void FWPC_blockTriangulateTest(const CLP& cmd)
//    {
//        bool v = cmd.isSet("v");
//        u64 numRows = cmd.getOr("m", 1000ull);
//
//        u64 numCols = numRows * cmd.getOr<double>("e", 2.4);
//        u64 weight = cmd.getOr("h", 2);
//
//        u64 binWidth = cmd.getOr("w", 100);
//        binWidth = std::min(binWidth, numCols);
//
//        u64 trials = cmd.getOr("t", 100);
//        u64 tt = cmd.getOr("tt", 0);
//
//
//        Matrix<u64> points(numRows, weight);
//        for (; tt < trials; ++tt)
//        {
//            PRNG prng(block(0, cmd.getOr("s", tt)));
//
//            std::set<u64> c;
//            //for (u64 i = 0; i < numRows; ++i)
//            //{
//
//            //    while (c.size() != h)
//            //        c.insert(prng.get<u64>() % numCols);
//
//            //    auto row = points[i];
//            //    std::copy(c.begin(), c.end(), row.begin());
//            //    c.clear();
//            //}
//            for (u64 i = 0; i < numRows; ++i)
//            {
//                //if (d)
//                //{
//                //    auto base = prng.get<u64>() % (n-d);
//                //    c.insert(base);
//
//                //    while (c.size() != h)
//                //        c.insert((base + prng.get<u64>() % d) % n);
//                //}
//                if (binWidth)
//                {
//                    auto numBins = (numCols + binWidth - 1) / binWidth;
//
//                    auto binIdx = u64(double(i) * numBins / numRows);
//
//                    //auto r = prng.get<u64>() % q;
//
//                    auto colBegin = (binIdx * numCols) / numBins;
//                    auto colEnd = ((binIdx + 1) * numCols) / numBins;
//                    auto nn = colEnd - colBegin;
//
//                    while (c.size() != weight)
//                        c.insert(prng.get<u64>() % nn + colBegin);
//
//                }
//
//                std::copy(c.begin(), c.end(), points[i].begin());
//                c.clear();
//            }
//
//            FWPC H(numCols, binWidth, points);
//
//
//            auto HH = H;
//            std::vector<std::array<u64, 3>> bb;
//            std::vector<u64> R, C;
//
//            if (v)
//                std::cout << H << std::endl
//                << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ " << std::endl;;
//
//            H.blockTriangulate(bb, R, C, v, false);
//            if (isBlockTriangular(H.mRows, numCols, bb) == false)
//                throw UnitTestFail(LOCATION);
//            //if (isSame(H.mRows, points, R, C) == false)
//            //    throw UnitTestFail(LOCATION);
//        }
//    }
//
//
//    void unitTest(CLP& cmd)
//    {
//
//        oc::TestCollection tests;
//        tests.add("LDPC.blockTriangulateTest16 ", LDPC_blockTriangulateTest<u16>);
//        tests.add("LDPC.blockTriangulateTest64 ", LDPC_blockTriangulateTest<u64>);
//        tests.add("FWPC.blockTriangulateTest   ", FWPC_blockTriangulateTest);
//
//
//
//        tests.runIf(cmd);
//    }
//
//    template<typename Set>
//    void doBench(u64 n, Timer& timer, std::string tag, Set& set)
//    {
//        timer.setTimePoint(tag + ".setup");
//
//        for (u64 i = 0; i < n; ++i)
//        {
//            set.insert(i);
//        }
//        timer.setTimePoint(tag + ".insert");
//
//        for (u64 i = 1; i < n; i += 2)
//        {
//            auto iter = set.find(i);
//            if (iter == set.end())
//                throw RTE_LOC;
//        }
//        timer.setTimePoint(tag + ".find");
//
//        for (u64 i = 0; i < n; i += 2)
//        {
//            auto iter = set.find(i);
//            set.erase(iter);
//        }
//        timer.setTimePoint(tag + ".find_erase");
//
//        while (set.size())
//        {
//            set.erase(set.begin());
//
//            //if (set.load_factor() < shink)
//            //    set.resize(set.size());
//        }
//
//        timer.setTimePoint(tag + ".begin_erase");
//
//    }
//
//
//
//
//    void ldpcMain(CLP& cmd)
//    {
//        if (cmd.isSet("u"))
//            return unitTest(cmd);
//
//        if(cmd.isSet("w"))
//            fwpc(cmd);
//        else
//            ldpc(cmd);
//
//    }
//
//    void ldpc(CLP& cmd)
//    {
//
//        bool v = cmd.isSet("v");
//        bool stats = cmd.isSet("stats");
//        PRNG prng(block(1, cmd.getOr("s", 0)));
//
//        // The of columns.
//        u64 n = cmd.getOr("n", 30ull);
//
//        // The number of constaints/rows
//        u64 m = n / cmd.getOr<double>("e", 2.4);
//
//
//        u64 rowWeight = cmd.getOr("h", 3);
//        u64 colWeight = cmd.getOr("c", 0);
//
//        if (colWeight)
//        {
//            assert(rowWeight > colWeight);
//            n = roundUpTo(n, rowWeight);
//            m = n * colWeight / rowWeight;
//        }
//        std::vector<u64> colIdxs;
//
//
//        u64 t = cmd.getOr("t", 1);
//
//        u64 w = cmd.getOr("w", 0);
//        u64 d = cmd.getOr("d", 0);
//        double exp = cmd.getOr("exp", 0.0);
//        Matrix<u64>points(m,rowWeight);
//        Timer timer;
//
//        if (exp)
//        {
//            std::exponential_distribution<double> expDist(1 / exp);
//            std::cout << "exp ";
//            for (u64 i = 0; i < 30; ++i)
//                std::cout << expDist(prng) << " ";
//            std::cout << std::endl;
//        }
//
//        double dur1(0), dur2(0);
//        std::set<u64> c;
//        for (u64 tt = 0; tt < t; ++tt)
//        {
//            if (colWeight)
//            {
//
//                colIdxs.resize(colWeight * n);
//                auto iter = colIdxs.begin();
//                for (u64 i = 0; i < n; ++i)
//                {
//                    for (u64 j = 0; j < colWeight; ++j)
//                    {
//                        *iter = i;
//                        ++iter;
//                    }
//                }
//
//                std::shuffle(colIdxs.begin(), colIdxs.end(), prng);
//            }
//
//            for (u64 i = 0; i < m; ++i)
//            {
//                //if (w)
//                //{
//                //    w = std::min(n, w);
//                //    auto q = (n + w - 1) / w;
//
//                //    auto r = u64(double(i) * q / m);
//
//                //    //auto r = prng.get<u64>() % q;
//
//                //    auto begin = n * r / q;
//                //    auto end = n * (r + 1) / q;
//                //    auto nn = end - begin;
//
//                //    while (c.size() != rowWeight)
//                //        c.insert(prng.get<u64>() % nn + begin);
//
//                //}
//                //else if (d)
//                //{
//                //    auto base = prng.get<u64>() % n;
//                //    c.insert(base);
//
//                //    while (c.size() != rowWeight)
//                //        c.insert((base + prng.get<u64>() % d) % n);
//                //}
//                //else if (exp)
//                //{
//
//                //    auto base = prng.get<u64>() % n;
//                //    c.insert(base);
//                //    std::exponential_distribution<double> expDist(1 / exp);
//
//                //    while (c.size() != rowWeight)
//                //        c.insert(u64(base + expDist(prng)) % n);
//                //}
//                //else
//                if(colWeight == 0)
//                {
//                    while (c.size() != rowWeight)
//                        c.insert(prng.get<u64>() % n);
//                }
//                else
//                {
//                    while (c.size() != rowWeight)
//                    {
//                        auto iter = --colIdxs.end();
//                        while(c.find(*iter) != c.end())
//                        {
//                            if (iter == colIdxs.begin())
//                            {
//                                std::cout << "failed to make matrix" << std::endl;
//                                return;
//                            }
//                            --iter;
//                        }
//                        c.insert(*iter);
//
//                        std::swap(*iter, colIdxs.back());
//                        colIdxs.pop_back();
//                    }
//
//                    //std::vector<> colSets
//                }
//
//                std::copy(c.begin(), c.end(), points[i].begin());
//
//                c.clear();
//            }
//
//
//            {
//                CuckooIndex<> cuckoo;
//                cuckoo.init(m, 40, 0, 3);
//                std::vector<block> inputs(m);
//                prng.get(inputs.data(), inputs.size());
//
//                auto start = timer.setTimePoint("");
//                cuckoo.insert(inputs, 0);
//                auto end = timer.setTimePoint("");
//                dur1 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
//            }
//
//            std::vector<std::array<u64, 3>> bb;
//            if(rowWeight == 2)
//            {
//
//                LDPC<u64, 2> H2(n, points);
//
//                //u64 maxCol = 0;
//                //for (u64 i = 0; i < n; ++i)
//                //    maxCol = std::max<u64>(maxCol, H.mCols[i].mRowIdxs.size());
//                //
//
//                if (v)
//                {
//                    std::cout << "--------------------------------" << std::endl;
//                    std::cout << H2 << std::endl;
//                    std::cout << "--------------------------------" << std::endl;
//                }
//
//                std::vector<u64> R, C;
//
//                auto start = timer.setTimePoint("");
//                H2.blockTriangulate(bb, R, C, v, stats, true);
//                auto end = timer.setTimePoint("");
//                dur2 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
//
//
//                timer.setTimePoint("triangulate");
//
//                if (v)
//                {
//                    std::cout << diff(H2.mRows, H2.mRows, bb, H2.cols()) << std::endl;
//                    std::cout << "--------------------------------" << std::endl;
//                }
//            }
//            else if (rowWeight == 3)
//            {
//
//                LDPC<u64, 3> H2(n, points);
//                if (v)
//                {
//                    std::cout << "--------------------------------" << std::endl;
//                    std::cout << H2 << std::endl;
//                    std::cout << "--------------------------------" << std::endl;
//                }
//
//                std::vector<u64> R, C;
//
//                auto start = timer.setTimePoint("");
//                H2.blockTriangulate(bb, R, C, v, stats, true);
//                auto end = timer.setTimePoint("");
//                dur2 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
//
//
//                timer.setTimePoint("triangulate");
//
//                if (v)
//                {
//                    std::cout << diff(H2.mRows, H2.mRows, bb, H2.cols()) << std::endl;
//                    std::cout << "--------------------------------" << std::endl;
//                }
//            }
//            else if (rowWeight == 10)
//            {
//
//                LDPC<u64, 10> H2(n, points);
//                if (v)
//                {
//                    std::cout << "--------------------------------" << std::endl;
//                    std::cout << H2 << std::endl;
//                    std::cout << "--------------------------------" << std::endl;
//                }
//
//                std::vector<u64> R, C;
//
//                auto start = timer.setTimePoint("");
//                H2.blockTriangulate(bb, R, C, v, stats, true);
//                auto end = timer.setTimePoint("");
//                dur2 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
//
//
//                timer.setTimePoint("triangulate");
//
//                if (v)
//                {
//                    std::cout << diff(H2.mRows, H2.mRows, bb, H2.cols()) << std::endl;
//                    std::cout << "--------------------------------" << std::endl;
//                }
//            }
//            else
//            {
//                std::cout << "h not implemented" << std::endl;
//                throw RTE_LOC;
//            }
//
//            std::cout << "blks " << bb.size() << std::endl;
//
//        }
//        //std::cout << "max col " << maxCol << " " << std::log2(m) << std::endl;
//        std::cout << dur1 / t << " " << dur2 / t << std::endl;
//        //H.partition(R, C, v);
//        //std::cout << "--------------------------------" << std::endl;
//        //std::cout << H << std::endl;
//
//        return;
//    }
//
//    template<typename Size> 
//    void fill(std::vector<u64>& c, u64 w, u64 nn, u64 colBegin, PRNG& prng)
//    {
//        while (c.size() != w)
//        {
//            auto col = prng.get<Size>() % nn + colBegin;
//            auto iter = std::find(c.begin(), c.end(), col);
//            if (iter == c.end())
//            {
//                c.push_back(col);
//            }
//        }
//    }
//
//
//    void fwpc(CLP& cmd)
//    {
//        bool v = cmd.isSet("v");
//        bool stats = cmd.isSet("stats");
//
//        // The number of constaints
//        u64 numRows = cmd.getOr("m", 30ull);
//        // The 
//        u64 numCols = numRows * cmd.getOr<double>("e", 2.4);
//        u64 weight = cmd.getOr("h", 2);
//        u64 t = cmd.getOr("t", 1);
//        PRNG prng(block(0, cmd.getOr("s", 0)));
//
//        u64 binWidth = cmd.getOr("w", 10);
//        binWidth = std::min(numCols, binWidth);
//        auto numBins = (numCols + binWidth - 1) / binWidth;
//
//        Matrix<u64> points(numRows, weight);
//        Timer timer;
//
//        libdivide::divider<u64> numRowsDiv(numRows);
//        libdivide::divider<u64> numBinsDiv(numBins);
//
//        double dur1(0), dur2(0);
//        std::vector<u64> c;
//        for (u64 i = 0; i < numRows; ++i)
//        {
//            auto binIdx = i * numBins / numRowsDiv;
//            auto colBegin = (binIdx * numCols) / numBinsDiv;
//            auto colEnd = ((binIdx + 1) * numCols) / numBinsDiv;
//            auto nn = colEnd - colBegin;
//            if (nn < std::numeric_limits<u16>::max())
//            {
//                fill<u16>(c, weight, nn, colBegin, prng);
//            }
//            else if (nn < std::numeric_limits<u32>::max())
//            {
//                fill<u32>(c, weight, nn, colBegin, prng);
//            }
//            else
//            {
//                fill<u64>(c, weight, nn, colBegin, prng);
//            }
//
//            memcpy(&points(i, 0), c.data(), sizeof(u64) * weight);
//            c.clear();
//        }
//
//
//        for (u64 i = 0; i < t; ++i)
//        {
//
//
//            if(cmd.isSet("cuckoo"))
//            {
//                CuckooIndex<> cuckoo;
//                cuckoo.init(numRows, 40, 0, 3);
//                std::vector<block> inputs(numRows);
//                prng.get(inputs.data(), inputs.size());
//
//                auto start = timer.setTimePoint("");
//                cuckoo.insert(inputs, 0);
//                auto end = timer.setTimePoint("");
//                dur1 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
//            }
//
//            {
//
//                //LDPC H2(m, n, h, points);
//                FWPC H;
//                H.insert(numCols, binWidth, points);
//                auto H2 = H;
//
//                //print(std::cout, points, numCols);
//
//                //u64 maxCol = 0;
//                //for (u64 i = 0; i < n; ++i)
//                //    maxCol = std::max<u64>(maxCol, H.mCols[i].mRowIdxs.size());
//                //
//
//                if (v)
//                {
//                    std::cout << "--------------------------------" << std::endl;
//                    std::cout << H << std::endl;
//                    std::cout << "--------------------------------" << std::endl;
//                }
//
//                std::vector<std::array<u64, 3>> bb;
//                std::vector<u64> R, C;            
//
//
//                auto start = timer.setTimePoint("");
//                H.blockTriangulate(bb, R, C, v, stats);
//                auto end = timer.setTimePoint("");
//                dur2 += std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
//
//
//                //timer.setTimePoint("triangulate");
//
//                if (v)
//                {
//                    //std::cout << diff(H.mRows, H2.mRows, bb) << std::endl;
//                    std::cout << "--------------------------------" << std::endl;
//                    std::cout << H << std::endl;
//                }
//            }
//        }
//        //std::cout << "max col " << maxCol << " " << std::log2(m) << std::endl;
//        std::cout << dur1 / t << " " << dur2 / t << std::endl;
//        //H.partition(R, C, v);
//        //std::cout << "--------------------------------" << std::endl;
//        //std::cout << H << std::endl;
//
//        return;
//    }
//
//}

namespace osuCrypto
{
    void ldpcMain(CLP& cmd)
    {
        tests::Mtx_add_test();
        tests::Mtx_mult_test();
        tests::Mtx_invert_test();
        tests::Mtx_block_test();
        tests::LdpcEncoder_diagonalSolver_test();
        tests::LdpcEncoder_encode_test();

    }
}