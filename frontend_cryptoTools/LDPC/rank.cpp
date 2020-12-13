#include "rank.h"
#include <Eigen/Dense>

#include "cryptoTools/Crypto/PRNG.h"
#include <numeric>

using namespace oc;





using Mtx = Eigen::Matrix<int, Eigen::Dynamic, Eigen::Dynamic>;


Mtx gaussianElim(Mtx mtx)
{
    auto rows = mtx.rows(); 
    auto cols = mtx.cols();

    u64 colIdx = 0ull;
    for (u64 i = 0; i < rows; ++i)
    {
        while (mtx(i, colIdx) == 0)
        {
            for (u64 j = i + 1; j < rows; ++j)
            {
                if (mtx(j, colIdx) == 1)
                {
                    mtx.row(i).swap(mtx.row(j));
                    --colIdx;
                    break;
                }
            }

            ++colIdx;

            if (colIdx == cols)
                return mtx;
        }

        for (u64 j = i + 1; j < rows; ++j)
        {
            if (mtx(j, colIdx))
            {
                for (u64 k = 0; k < cols; ++k)
                {
                    mtx(j, k) ^= mtx(i, k);
                }
            }
        }

    }

    return mtx;

}

std::set<u64> sampleCol(u64 begin, u64 end, u64 weight, bool diag, PRNG& prng)
{
    std::set<u64> idxs;

    auto n = end - begin;
    assert(n >= weight);

    if (diag)
    {
        idxs.insert(begin);
        ++begin;
        --n;
        --weight;
    }

    if (n < 3 * weight)
    {
        auto nn = std::min(3 * weight, n);
        std::vector<u64> set(nn);
        std::iota(set.begin(), set.end(), begin);

        std::shuffle(set.begin(), set.end(), prng);

        idxs.insert(set.begin(), set.begin() + weight);
    }
    else
    {
        while (idxs.size() != weight)
        {
            idxs.insert(prng.get<u64>() % n + begin);
        }
    }


    return idxs;
}


u64 numNonzeroRows(const Mtx& mtx)
{
    u64 r = 0;
    for (u64 i = 0; i < mtx.rows(); ++i)
    {
        if (mtx.row(i).isZero())
            ++r;
    }

    return mtx.rows() - r;
}

u64 rank(const Mtx& mtx)
{
    Mtx m2 = gaussianElim(mtx);
    return numNonzeroRows(m2);
}

void rank(CLP& cmd)
{
    u64 rows = cmd.getOr("m", 20);
    u64 cols = rows * cmd.getOr("e", 2.0);
    u64 w = cmd.getOr("w", 4);
    
    assert(cols > rows);
    assert(rows > w);

    Mtx mtx(rows, cols);
    mtx.setZero();

    PRNG prng(block(0, cmd.getOr("s", 0)));

    u64 last = ~0ull;
    for (u64 i = 0; i < cols; ++i)
    {
        u64 diag = i - rows - w;
        auto start = std::max<i64>(0, diag);
        auto s = sampleCol(start, rows, w, start==diag, prng);

        for (auto ss : s)
        {
            assert(ss >= start);

            mtx(ss, i) = 1;
        }
        //auto end = std::min<u64>(rows, start + w);

        //for (u64 j = start; j < start + w; ++j)
        //{
        //    mtx(j, i) = prng.getBit();
        //}

        //if (start != last)
        //{
        //    mtx(start, i) = 1;
        //}

        //last = start;
    }


    std::cout << mtx << std::endl << std::endl;


    auto m2 = mtx.block(0, 0, rows, rows).transpose();
    std::cout << m2 << std::endl << std::endl;

    auto m3 = gaussianElim(m2);


    std::cout << m3 << std::endl << std::endl;

    auto r = rank(m3);
    std::cout << "rank " << r << " / " << m3.rows() << std::endl;
    return;
    //Matrix5x3 m = Matrix5x3::Random();
    //std::cout << "Here is the matrix m:" << endl << m << endl;
    //Eigen::FullPivLU<Mtx> lu(mtx);
    //std::cout << "Here is, up to permutations, its LU decomposition matrix:"
    //    << std::endl << lu.matrixLU() << std::endl;
    //std::cout << "Here is the L part:" << std::endl;
    //Mtx l = Mtx::Identity();
    //l.block<5, 3>(0, 0).triangularView<StrictlyLower>() = lu.matrixLU();
    //cout << l << endl;
    //cout << "Here is the U part:" << endl;
    //Matrix5x3 u = lu.matrixLU().triangularView<Upper>();
    //cout << u << endl;
    //cout << "Let us now reconstruct the original matrix m:" << endl;
    //cout << lu.permutationP().inverse() * l * u * lu.permutationQ().inverse() << endl;

}