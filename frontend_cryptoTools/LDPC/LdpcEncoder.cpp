#include "LdpcEncoder.h"
#include <eigen/dense>
#include <set>
#include "cryptoTools/Crypto/PRNG.h"
#include "LdpcSampler.h"

namespace osuCrypto
{

    bool LdpcEncoder::init(SparseMtx H, u64 gap)
    {

#ifndef NDEBUG
        for (u64 i = H.cols() - H.rows() + gap, j = 0; i < H.cols(); ++i, ++j)
        {
            auto row = H.row(j);
            assert(row[row.size() - 1] == i);
        }
#endif
        assert(gap);

        auto c0 = H.cols() - H.rows();
        auto c1 = c0 + gap;
        auto r0 = H.rows() - gap;

        mN = H.cols();
        mM = H.rows();
        mGap = gap;

        mH = H;

        mA = H.block(0, 0, r0, c0);
        mB = H.block(0, c0, r0, gap);
        mC = H.block(0, c1, r0, H.rows() - gap);
        mD = H.block(r0, 0, gap, c0);
        mE = H.block(r0, c0, gap, gap);
        mF = H.block(r0, c1, gap, H.rows() - gap);
        mCInv.init(mC);

        
        //SparseMtx FC = mF * mC.invert();
        //auto points = FC.points();

        //for (auto& p : points)
        //    p.mRow += r0;

        //for (u64 i = 0; i < mM; ++i)
        //    points.push_back({ i,i });

        //SparseMtx M(mM, mM, points);

        //auto H2 = M.mult(mH);
        //auto ep = H2.block(r0, c0, gap, gap);

        //std::cout << "FC\n" << FC << std::endl;
        //std::cout << "M\n" << M << std::endl;
        //std::cout << "H\n" << H << std::endl;
        //std::cout << "H2\n" << H2 << std::endl;
        //std::cout << "ep\n" << ep << std::endl;


        //for (u64 i = 0; i < mGap; ++i)
        //    points.pop_back();
        //SparseMtx M3(mM, mM, points);

        //auto H3 = M3.mult(mH);
        //auto FCB3 = H3.block(r0, c0, gap, gap);
        //auto FCB = FC * mB;
        //std::cout << "M3\n" << M3 << std::endl;
        //std::cout << "H3\n" << H3 << std::endl;
        //std::cout << "FCB3\n" << FCB3 << std::endl;
        //std::cout << "FCB \n" << FCB << std::endl;

        //assert(FCB3 == FCB);


        SparseMtx CB; 

        // CB = C^-1 B
        mCInv.mult(mB, CB);

        assert(mC.invert().mult(mB) == CB);



        // Ep = F C^-1 B
        mEp = mF.mult(CB);

        //// Ep = F C^-1 B + E
        mEp += mE;


        //(- F / C) B + E
        //mEp = FCB + mE;
        //std::cout << "Ep\n" << mEp << std::endl;
        //std::cout << "ep\n" << ep << std::endl;

        //assert(ep == mEp);

        //auto ee = mEp;

        mEp = mEp.invert();
        //std::cout << ee << "\n" << (bool)mEp.rows() << std::endl;


        // Ep = (F C^-1 B + E)^-1
        //mEp = mEp.invert();


        return (mEp.rows() != 0);

    }

    void LdpcEncoder::encode(span<u8> c, span<const u8> mm)
    {
        assert(mm.size() == mM);
        assert(c.size() == mN);

        auto s = mM - mGap;

        auto iter = c.begin() + mM;
        span<u8> m(c.begin(), iter);
        span<u8> p(iter, iter + mGap); iter += mGap;
        span<u8> pp(iter, c.end());
        std::vector<u8> t(s);
        assert(pp.size() == s);

        // m = mm
        std::copy(mm.begin(), mm.end(), m.begin());
        std::fill(c.begin() + mM, c.end(), 0);

        // pp = A * m
        mA.multAdd(m, pp);

        // t = C^-1 pp      = C^-1 A m
        mCInv.mult(pp, t);

        // p = - F t + D m  = -F C^-1 A m + D m
        mF.multAdd(t, p);
        mD.multAdd(m, p);

        // p = - Ep p       = -Ep (-F C^-1 A m + D m)
        t = mEp.mult(p);
        std::copy(t.begin(), t.end(), p.begin());

        // pp = pp + B p    
        mB.multAdd(p, pp);

        // pp = C^-1 pp 
        mCInv.mult(pp, pp);

        //for (u64 i = 0; i < mM - mGap; ++i)
        //    std::cout << ". ";
        //std::cout << std::endl;

    }

    void DiagInverter::mult(span<const u8> y, span<u8> x)
    {
        // solves for x such that y = M x, ie x := H^-1 y 
        assert(mC);
        assert(mC->rows() == y.size());
        assert(mC->cols() == x.size());
        for (u64 i = 0; i < mC->rows(); ++i)
        {
            auto& row = mC->row(i);
            x[i] = y[i];
            for (u64 j = 0; j < row.size() - 1; ++j)
                x[i] ^= x[row[j]];

        }
    }

    void DiagInverter::mult(const SparseMtx& y, SparseMtx& x)
    {
        auto n = mC->rows();
        assert(n == y.rows());
        //assert(n == x.rows());
        //assert(y.cols() == x.cols());

        auto xNumRows = n;
        auto xNumCols = y.cols();

        std::vector<u64>& xCol = x.mDataCol; xCol.reserve(y.mDataCol.size());
        std::vector<u64>
            colSizes(xNumCols),
            rowSizes(xNumRows);

        for (u64 c = 0; c < y.cols(); ++c)
        {
            auto cc = y.col(c);
            auto yIter = cc.begin();
            auto yEnd = cc.end();

            auto xColBegin = xCol.size();
            for (u64 i = 0; i < n; ++i)
            {
                u8 bit = 0;
                if (yIter != yEnd && *yIter == i)
                {
                    bit = 1;
                    ++yIter;
                }

                auto rr = mC->row(i);
                auto mIter = rr.begin();
                auto mEnd = rr.end() - 1;

                auto xIter = xCol.begin() + xColBegin;
                auto xEnd = xCol.end();

                while (mIter != mEnd && xIter != xEnd)
                {
                    if (*mIter < *xIter)
                        ++mIter;
                    else if (*xIter < *mIter)
                        ++xIter;
                    else
                    {
                        bit ^= 1;
                        ++xIter;
                        ++mIter;
                    }
                }

                if (bit)
                {
                    xCol.push_back(i);
                    ++rowSizes[i];
                }
            }
            colSizes[c] = xCol.size();
        }

        x.mCols.resize(colSizes.size());
        auto iter = xCol.begin();
        for (u64 i = 0; i < colSizes.size(); ++i)
        {
            auto end = xCol.begin() + colSizes[i];
            x.mCols[i] = SparseMtx::Col(span<u64>(iter, end));
            iter = end;
        }

        x.mRows.resize(rowSizes.size());
        x.mDataRow.resize(x.mDataCol.size());
        iter = x.mDataRow.begin();
        //auto prevSize = 0ull;
        for (u64 i = 0; i < rowSizes.size(); ++i)
        {
            auto end = iter + rowSizes[i];

            rowSizes[i] = 0;
            //auto ss = rowSizes[i];
            //rowSizes[i] = rowSizes[i] - prevSize;
            //prevSize = ss;

            x.mRows[i] = SparseMtx::Row(span<u64>(iter, end));
            iter = end;
        }

        iter = xCol.begin();
        for (u64 i = 0; i < x.cols(); ++i)
        {
            for (u64 j : x.col(i))
            {
                x.mRows[j][rowSizes[j]++] = i;
            }
        }

    }

}


void osuCrypto::tests::LdpcEncoder_diagonalSolver_test()
{
    u64 n = 10;
    u64 m = n;
    u64 w = 4;
    u64 t = 10;

    PRNG prng(block(0, 0));
    std::vector<u8> x(n), y(n);
    for (u64 tt = 0; tt < t; ++tt)
    {
        SparseMtx H = sampleTriangular(n, 0.5, prng);

        //std::cout << H << std::endl;

        for (auto& yy : y)
            yy = prng.getBit();

        DiagInverter HInv(H);

        HInv.mult(y, x);

        auto z = H.mult(x);

        assert(z == y);

        auto Y = sampleFixedColWeight(n, w, 3, prng);

        SparseMtx X;

        HInv.mult(Y, X);

        auto Z = H * X;

        assert(Z == Y);

    }




    return;
}

void osuCrypto::tests::LdpcEncoder_encode_test()
{

    u64 rows = 16;
    u64 cols = rows * 2;
    u64 colWeight = 4;
    u64 dWeight = 3;
    u64 gap = 6;

    auto k = cols - rows;

    assert(gap >= dWeight);

    PRNG prng(block(0, 2));


    SparseMtx H;
    LdpcEncoder E;


    //while (b)
    for(u64 i =0; i < 40; ++i)
    {
        bool b = true;
        //std::cout << " +====================" << std::endl;
        while (b)
        {
            H = sampleTriangularBand(rows, cols, colWeight, gap, dWeight, prng);
            //H = sampleTriangular(rows, cols, colWeight, gap, prng);
            b = !E.init(H, gap);
        }

        //std::cout << H << std::endl;

        std::vector<u8> m(k), c(cols);

        for (auto& mm : m)
            mm = prng.getBit();


        E.encode(c, m);

        auto ss = H.mult(c);

        //for (auto sss : ss)
        //    std::cout << int(sss) << " ";
        //std::cout << std::endl;
        assert(ss == std::vector<u8>(H.rows(), 0));

    }
    return;

}
