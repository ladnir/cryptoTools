#include "rank.h"
#include <Eigen/Dense>
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitIterator.h"
#include <numeric>
#include <iomanip>
#include <future>

#include "Mtx.h"
#include <deque>
#include "LdpcSampler.h"
using namespace oc;





//using Mtx = Eigen::Matrix<int, Eigen::Dynamic, Eigen::Dynamic>;

DenseMtx gaussianElim(DenseMtx mtx)
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


u64 numNonzeroRows(const DenseMtx& mtx)
{
    u64 r = 0;
    for (u64 i = 0; i < mtx.rows(); ++i)
    {
        if (mtx.row(i).isZero())
            ++r;
    }

    return mtx.rows() - r;
}

u64 rank(const DenseMtx& mtx)
{
    DenseMtx m2 = gaussianElim(mtx);
    return numNonzeroRows(m2);
}

//struct NChooseK
//{
//    u64 mN;
//    u64 mK;
//
//    std::vector<u64> mSet;
//
//    NChooseK(u64 n, u64 k, u64 offset = 0)
//        : mN(n)
//        , mK(k)
//    {
//        assert(k <= n);
//        mSet.resize(k);
//        std::iota(mSet.begin(), mSet.end(), offset);
//    }
//
//    const std::vector<u64>& operator*() const
//    {
//        return mSet;
//    }
//
//    void operator++()
//    {
//        auto back = mN - 1;
//
//        while (mSet.size() && mSet.back() == back)
//        {
//            mSet.pop_back();
//            --back;
//        }
//        if (mSet.size())
//        {
//            back = ++mSet.back();
//
//            while (mSet.size() != mK)
//                mSet.push_back(++back);
//        }
//    }
//
//    explicit operator bool() const
//    {
//        return mSet.size();
//    }
//
//};


std::vector<u64> ithCombination(u64 index, u64 n, u64 k)
{
    //'''Yields the items of the single combination that would be at the provided
    //(0-based) index in a lexicographically sorted list of combinations of choices
    //of k items from n items [0,n), given the combinations were sorted in 
    //descending order. Yields in descending order.
    //'''
    u64 nCk = 1;
    u64 nMinusI = n;
    u64 iPlus1 = 1;

    std::vector<u64> set(k);
    // nMinusI, iPlus1 in zip(range(n, n - k, -1), range(1, k + 1)):
    for (; nMinusI != n - k; --nMinusI, ++iPlus1)
    {
        nCk *= nMinusI;
        nCk /= iPlus1;
    }

    //std::cout << "nCk " << nCk << std::endl;

    auto curIndex = nCk;
    for (auto kk = k; kk != 0ull; --kk)//in range(k, 0, -1):
    {
        //std::cout << "kk " << kk << " " <<  nCk << std::endl;
        nCk *= kk;
        nCk /= n;
        while (curIndex - nCk > index) {
            curIndex -= nCk;
            nCk *= (n - kk);
            nCk -= nCk % kk;
            n -= 1;
            nCk /= n;
        }
        n -= 1;

        set[kk - 1] = n;
    }
    return set;
}

u64 choose(u64 n, u64 k)
{
    if (k == 0) return 1;
    return (n * choose(n - 1, k - 1)) / k;
}

struct NChooseK
{
    u64 mN;
    u64 mK;
    u64 mI, mEnd;
    std::vector<u64> mSet;

    NChooseK(u64 n, u64 k, u64 begin = 0, u64 end = -1)
        : mN(n)
        , mK(k)
        , mI(begin)
        , mEnd(std::min<u64>(choose(n, k), end))
    {
        assert(k <= n);
        mSet = ithCombination(begin, n, k);
    }

    const std::vector<u64>& operator*() const
    {
        return mSet;
    }

    void operator++()
    {
        ++mI;
        assert(mI <= mEnd);

        u64 i = 0;
        while (i < mK - 1 && mSet[i] + 1 == mSet[i + 1])
            ++i;

        //if (i == mK - 1 && mSet.back() == mN - 1)
        //{
        //    mSet.clear();
        //    return;
        //    //assert(mSet.back() != mN - 1);
        //}

        ++mSet[i];
        for (u64 j = 0; j < i; ++j)
            mSet[j] = j;
    }

    explicit operator bool() const
    {
        return mI < mEnd;
    }

};

bool isZero(const span<block>& sum)
{
    for (auto& b : sum)
        if (b != ZeroBlock)
        {
            return false;
            break;
        }
    return true;
}
bool isEq(const span<const block>& u, const span<const block>& v)
{
    assert(u.size() == v.size());
    return memcmp(u.data(), v.data(), v.size_bytes()) == 0;
}

template <typename T>
class queue
{
private:
    std::mutex              d_mutex;
    std::condition_variable d_condition;
    std::deque<T>           d_queue;
public:
    void push(T const& value) {
        {
            std::unique_lock<std::mutex> lock(this->d_mutex);
            d_queue.push_front(value);
        }
        this->d_condition.notify_one();
    }
    T pop() {
        std::unique_lock<std::mutex> lock(this->d_mutex);
        this->d_condition.wait(lock, [=] { return !this->d_queue.empty(); });
        T rc(std::move(this->d_queue.back()));
        this->d_queue.pop_back();
        return rc;
    }
};


std::pair<double, std::vector<u64>> minDist(const DenseMtx& mtx, bool verbose, u64 numThreads)
{
    assert(mtx.rows() < mtx.cols());

    u64 percision = 2;
    u64 p = pow(10, percision);


    std::mutex mut;
    queue<std::function<void()>> queue;
    std::vector<std::thread> thrds(numThreads);
    for (u64 i = 0; i < thrds.size(); ++i)
    {
        thrds[i] = std::thread([&mut, &queue, i](){

            while(true)
            {
                std::function<void()> fn = queue.pop();
                if (!fn)
                    return;
                fn();
            }
            });
    }


    u64 dd = mtx.mData.cols();
#define ASSUME_DD_1
#ifdef ASSUME_DD_1
    assert(dd == 1);
#endif

    for (u64 weight = 2; weight < mtx.rows(); ++weight)
    {
        auto total = choose(mtx.cols(), weight);
        u64 next = 0;
        std::atomic<u64> ii = 0;
        //std::atomic<u64> rem = numThreads;

        bool done = false;
        using Ret = std::pair<double, std::vector<u64>>;
        std::vector<std::promise<Ret>> prom(numThreads);
        //auto fu = prom.get_future();

        

        for (u64 i = 0; i < numThreads; ++i)
        {
            queue.push([&, i, weight]() {
                

                auto begin = i * total / numThreads;
                auto end = (i + 1) * total / numThreads;
                auto iter = NChooseK(mtx.cols(), weight, begin, end);
                u64& mI = iter.mI;
                std::vector<u64> set;
#ifdef ASSUME_DD_1
                block sum;
#else
                std::vector<block> sum(dd);
#endif
                while (begin++ != end && !done)
                {
                    set = *iter;

                    if (verbose && ii >= next)
                    {
                        std::lock_guard<std::mutex> lock(mut);
                        if (verbose && ii >= next)
                        {
                            auto cur = ii * p / total;
                            next = (cur + 1) * total / p;;
                            std::cout << "\r" << weight << "." << std::setw(percision) << std::setfill('0') << cur << "       " << std::flush;
                        }
                    }
#ifdef ASSUME_DD_1
                    auto ptr = mtx.mData.data();
                    sum = ptr[set[0]];
                    for (u64 i = 1; i < weight; ++i)
                    {
                        auto col = ptr[set[i]];
                        sum = sum ^ col;
                    }

                    auto linDep = sum == ZeroBlock;
#else

                    auto v = mtx.col(set[0]);
                    std::copy(v.data(), v.data() + dd, sum.data());
                    
                    for (u64 i = 1; i < weight; ++i)
                    {
                        auto col = mtx.col(set[i]);
                        for (u64 j = 0; j < dd; ++j)
                            sum[j] = sum[j] ^ col[j];
                    }

                    auto linDep = isZero(sum);
#endif
                    if (linDep)
                    {
                        std::lock_guard<std::mutex> lock(mut);
                        if (verbose)
                        {
                            std::cout << std::endl;
                        }
                        done = true;

                        prom[i].set_value(std::make_pair(weight + ii / double(total), set));
                        return;
                    }

                    ++ii;


                    //++iter;
                    {
                        //++(mI);
                        //assert(mI <= iter.mEnd);

                        u64 i = 0;
                        while (i < iter.mK - 1 && iter.mSet[i] + 1 == iter.mSet[i + 1])
                            ++i;

                        ++iter.mSet[i];
                        for (u64 j = 0; j < i; ++j)
                            iter.mSet[j] = j;
                    }
                }
                
                prom[i].set_value({});
                return;
            });
        }


        Ret ret;
        for (u64 i = 0; i < numThreads; ++i)
        {
            auto cc = prom[i].get_future().get();
            if (cc.second.size())
                ret = cc;
        }

        if (done)
        {
            for (u64 i = 0; i < numThreads; ++i)
                queue.push({});
            for (u64 i = 0; i < numThreads; ++i)
                thrds[i].join();
            return ret;
        }

    }
    assert(0);
    return {};
}

std::pair<double, std::vector<u64>> minDist(const DenseMtx& mtx, bool verbose)
{
    assert(mtx.rows() < mtx.cols());

    u64 percision = 2;
    u64 p = pow(10, percision);

    for (u64 weight = 2; weight < mtx.rows(); ++weight)
    {
        auto iter = NChooseK(mtx.cols(), weight);
        auto total = choose(mtx.cols(), weight);
        u64 prev = -1;
        u64 ii = 0;
        std::vector<block> sum(mtx.mData.cols());

        while (iter)
        {
            auto& set = *iter;

            auto cur = ii * p / total;
            if (verbose && prev != cur)
            {
                prev = cur;
                std::cout << "\r" << weight << "." << std::setw(percision) << std::setfill('0') << cur << "       " << std::flush;
            }

            auto v = mtx.col(set[0]);
            std::copy(v.begin(), v.end(), sum.begin());

            for (u64 i = 1; i < set.size(); ++i)
            {
                auto col = mtx.col(set[i]);
                for (u64 j = 0; j < sum.size(); ++j)
                    sum[j] = sum[j] ^ col[j];
            }

            if (isZero(sum))
            {
                if (verbose)
                    std::cout << std::endl;
                return std::make_pair(weight + ii / double(total), set);
            }

            ++ii;
            ++iter;
        }
    }
    assert(0);
    return {};
}

struct selectPrt
{
    const DenseMtx& mMtx;
    const std::vector<u64>& mCols;

    selectPrt(const DenseMtx& m, const std::vector<u64>& c)
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

//
//DenseMtx uniformFixedColWeight(u64 rows, u64 cols, u64 w, PRNG& prng)
//{
//    DenseMtx mtx(rows, cols);
//    mtx.setZero();
//    std::vector<u64> rem; rem.reserve(cols * w);
//    for (u64 i = 0; i < cols; ++i)
//    {
//        for (u64 j = 0; j < w; ++j)
//            rem.push_back(i);
//    }
//
//    std::shuffle(rem.begin(), rem.end(), prng);
//
//    while (rem.size())
//    {
//        auto i = prng.get<u64>() % rows;
//        mtx(i, rem.back()) = 1;
//        rem.pop_back();
//    }
//    return mtx;
//}

void rank(CLP& cmd)
{

    //u64 n = 6, k = 4;

    //NChooseK nCk(n, k);
    //u64 i = 0;
    //while (nCk)
    //{
    //    auto set0 = *nCk;
    //    auto set1 = ithCombination(i, n, k);

    //    std::cout << i << ":\n";
    //    for (u64 j = 0; j < k; ++j)
    //        std::cout << set0[j] << " ";
    //    std::cout << "  \n";
    //    for (u64 j = 0; j < k; ++j)
    //        std::cout << set1[j] << " ";
    //    std::cout << std::endl;

    //    ++i;
    //    ++nCk;
    //}
    //return;

    u64 rows = cmd.getOr("m", 20);
    u64 cols = rows * cmd.getOr("e", 2.0);
    u64 weight = cmd.getOr("w", 4);
    auto gaps = cmd.getManyOr<u64>("g", { 0 });

    u64 trials = cmd.getOr("t", 1);
    bool verbose = cmd.isSet("v");
    u64 thrds = cmd.getOr("thrds", std::thread::hardware_concurrency());

    assert(cols > rows);
    assert(rows > weight);
    PRNG prng(block(0, cmd.getOr("s", 0)));

    DenseMtx mtx(rows, cols);

    for (auto gap : gaps)
    {

        u64 dWeight = cmd.getOr("wd", (1 + gap) / 2);
        double avg = 0;

        for (u64 t = 0; t < trials; ++t)
        {
            mtx.setZero();


            if (gap)
            {
                mtx = sampleTriangularBand(rows, cols, weight, gap, dWeight, prng).dense();
            }
            else
            {
                mtx = sampleFixedColWeight(rows, cols, weight, prng).dense();

            }

            auto d = minDist(mtx, verbose, thrds);

            if (verbose)
            {
                std::cout << " " << d.first;
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