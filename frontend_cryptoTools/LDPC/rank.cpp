#include "rank.h"
#include <Eigen/Dense>
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <numeric>
#include <iomanip>

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

struct NChooseK
{
    u64 mN;
    u64 mK;
    std::vector<u64> mSet;

    NChooseK(u64 n, u64 k)
        : mN(n)
        , mK(k)
    {
        assert(k <= n);
        mSet.resize(k);
        std::iota(mSet.begin(), mSet.end(), 0);
    }

    const std::vector<u64>& operator*() const
    {
        return mSet;
    }

    void operator++()
    {
        auto back = mN - 1;

        while (mSet.size() && mSet.back() == back)
        {
            mSet.pop_back();
            --back;
        }
        if (mSet.size())
        {
            back = ++mSet.back();

            while (mSet.size() != mK)
                mSet.push_back(++back);
        }
    }

    explicit operator bool() const
    {
        return mSet.size();
    }

};
u64 choose(u64 n, u64 k)
{
    if (k == 0) return 1;
    return (n * choose(n - 1, k - 1)) / k;
}

std::pair<double, std::vector<u64>> minDist(const Mtx& mtx, bool verbose)
{
    assert(mtx.rows() < mtx.cols());

    for (u64 weight = 2; weight < mtx.rows(); ++weight)
    {
        auto iter = NChooseK(mtx.cols(), weight);
        auto total = choose(mtx.cols(), weight);
        u64 prev = -1;
        u64 i = 0;
        u64 percision = 2;
        u64 p = pow(10, percision);

        while (iter)
        {
            auto& set = *iter;

            auto cur = i * p / total;
            if (verbose && prev != cur)
            {
                prev = cur;
                std::cout << "\r" << weight << "." << std::setw(percision) << std::setfill('0') << cur << "       " << std::flush;
            }

            //std::cout << "[";
            //for (auto ss : set)
            //    std::cout << ss << " ";
            //std::cout << "]" << std::endl;

            Mtx sum = mtx.col(set[0]);
            for (u64 i = 1; i < set.size(); ++i)
            {
                auto col = mtx.col(set[i]);
                for (u64 j = 0; j < mtx.rows(); ++j)
                    sum(j) ^= col(j);
            }


            if (sum.isZero())
            {
                if(verbose)
                std::cout << std::endl;
                return std::make_pair(weight + i / double(total), set);
            }

            ++i;
            ++iter;
        }

    }
    assert(0);
    return {};
}

struct selectPrt
{
    const Mtx& mMtx;
    const std::vector<u64>& mCols;

    selectPrt(const Mtx& m, const std::vector<u64>& c)
        : mMtx(m)
        , mCols(c)
    {}
};

std::ostream& operator<<(std::ostream& o, const selectPrt& p)
{
    for (u64 i = 0; i < p.mMtx.rows(); ++i)
    {
        auto iter = p.mCols.begin();
        for (u64 j = 0; j < p.mMtx.cols(); ++j)
        {
            if (iter != p.mCols.end() && *iter == j)
                o << Color::Green;

            o << p.mMtx(i, j) << " ";

            if (iter != p.mCols.end() && *iter == j)
            {
                o << Color::Default;
                ++iter;
            }
        }

        o << std::endl;
    }
    return o;
}


Mtx uniformFixedColWeight(u64 rows, u64 cols, u64 w, PRNG& prng)
{
    Mtx mtx(rows, cols);
    mtx.setZero();
    std::vector<u64> rem; rem.reserve(cols * w);
    for (u64 i = 0; i < cols; ++i)
    {
        for (u64 j = 0; j < w; ++j)
            rem.push_back(i);
    }

    std::shuffle(rem.begin(), rem.end(), prng);

    while (rem.size())
    {
        auto i = prng.get<u64>() % rows;
        mtx(i, rem.back()) = 1;
        rem.pop_back();
    }
    return mtx;
}

void rank(CLP& cmd)
{
    u64 rows = cmd.getOr("m", 20);
    u64 cols = rows * cmd.getOr("e", 2.0);
    u64 weight = cmd.getOr("w", 4);
    u64 dWeight = cmd.getOr("wd", 1);

    auto gaps = cmd.getManyOr<u64>("g", { 0 });
    u64 trials = cmd.getOr("t", 1);
    bool verbose = cmd.isSet("v");

    assert(cols > rows);
    assert(rows > weight);
    PRNG prng(block(0, cmd.getOr("s", 0)));

    Mtx mtx(rows, cols);

    for (auto gap : gaps)
    {

        double avg = 0;

        for (u64 t = 0; t < trials; ++t)
        {

            mtx.setZero();


            if (0)
            {
                u64 last = ~0ull;
                for (u64 i = 0; i < cols; ++i)
                {
                    u64 diag = i - rows - weight;
                    auto start = 0; std::max<i64>(0, diag);
                    auto s = sampleCol(start, rows, weight, start == diag, prng);

                    for (auto ss : s)
                    {
                        assert(ss >= start);

                        mtx(ss, i) = 1;
                    }
                }
            }
            else if (gap)
            {
                mtx.block(0, 0, rows, cols - rows) = uniformFixedColWeight(rows, cols - rows, weight, prng);

                auto b = cols - rows;
                for (u64 i = 0; i < rows; ++i)
                {

                    mtx(i, b + i) = 1;

                    auto s = sampleCol(0, gap, dWeight, false, prng);

                    for (auto ss : s)
                        mtx((ss + i + 1) % rows, b + i) = 1;

                    //for (u64 j = i+1; j < i + gap; ++j)
                    //    mtx(j % rows, b + i) = prng.getBit();
                    //mtx((i + gap) % rows, b + i) = 1;
                }
            }
            else
            {
                mtx = uniformFixedColWeight(rows, cols, weight, prng);

            }

            //std::cout << mtx << std::endl << std::endl;

            auto d = minDist(mtx, verbose);
            std::cout << " " << d.first;

            if (verbose)
            {
                std::cout << "\n" << selectPrt(mtx, d.second) << std::endl;
            }

            avg += d.first;
        }


        std::cout << " ~~ " << gap << " " << avg / trials << std::endl;

    }
    //std::cout << "minDist = " << d.size() << std::endl
    //    << "[";
    //for (u64 i = 0; i < d.size(); ++i)
    //    std::cout << d[i] << " ";
    //std::cout << "]" << std::endl;


    //std::cout << selectPrt(mtx, d) << std::endl;

    //auto m2 = mtx.block(0, 0, rows, rows).transpose();
    //std::cout << m2 << std::endl << std::endl;

    //auto m3 = gaussianElim(m2);

    //std::cout << m3 << std::endl << std::endl;

    //auto r = rank(m3);
    //std::cout << "rank " << r << " / " << m3.rows() << std::endl;
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