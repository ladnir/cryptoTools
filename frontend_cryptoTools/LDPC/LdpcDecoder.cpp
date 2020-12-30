#include "LdpcDecoder.h"
#include <cassert>

namespace osuCrypto {

    void LdpcDecoder::init(u64 rows, u64 cols, const std::vector<std::array<u64, 2>>& H)
    {
        assert(cols > rows);
        mK = cols - rows;

        mCols.resize(cols);
        mRows.resize(rows);

        mR.resize(rows, cols);
        mM.resize(rows, cols);

        mW.resize(cols);

        for (u64 i = 0; i < H.size(); ++i)
        {
            mRows[H[i][0]].push_back(H[i][1]);
            mCols[H[i][1]].push_back(H[i][0]);
        }
    }


    std::vector<u8> LdpcDecoder::bpDecode(span<u8> codeword, u64 maxIter)
    {
        assert(codeword.size() == mCols.size());

        std::array<double, 2> wVal{ { (1 - mP) / mP, mP / (1 - mP)} };

        for (u64 i = 0; i < mCols.size(); ++i)
        {
            assert(codeword[i] < 2);
            mW[i] = wVal[codeword[i]];
        }

        std::vector<u8> c(mCols.size());
        std::vector<double> rr; rr.reserve(100);
        for (u64 ii = 0; ii < maxIter; ii++)
        {
            for (u64 j = 0; j < mRows.size(); ++j)
            {
                rr.resize(mRows[j].size());
                for (u64 i : mRows[j])
                {
                    // \Pi_{k in Nj \ {i} }  (r_k^j + 1)/(r_k^j - 1)
                    double v = 1;

                    for (u64 k : mRows[j])
                    {
                        if (k != i)
                        {
                            auto r = mR[j][k];
                            v *= (r + 1) / (r - 1);
                        }
                    }

                    // m_j^i 
                    mM(j, i) = (v + 1) / (v - 1);
                }
            }

            // i indexes a column, [1,...,n]
            for (u64 i = 0; i < mCols.size(); ++i)
            {
                // j indexes a row, [1,...,m]
                for (u64 j : mCols[i])
                {
                    // r_i^j = w_i * Pi_{k in Ni \ {j} } m_k^i
                    mR(j, i) = mW[i];

                    for (u64 k : mCols[i])
                    {
                        if (k != j)
                        {
                            mR(j, i) *= mM(i, k);
                        }
                    }
                }
            }



            // i indexes a column, [1,...,n]
            for (u64 i = 0; i < mCols.size(); ++i)
            {

                //L(ci | wi, m^i)
                double L = mW[i];
                for (u64 k : mCols[i])
                {
                    L *= mM(i, k);
                }

                c[i] = (L >= 1) ? 0 : 1;
            }

            bool isCW = true;
            for (u64 j = 0; j < mRows.size(); ++j)
            {
                u8 sum = 0;

                for (u64 i : mRows[j])
                {
                    sum ^= codeword[i];
                }

                if (sum)
                {
                    isCW = false;
                    if (ii == maxIter)
                        return {};
                    else
                        break;
                }
            }

            if (isCW)
            {
                return c;
            }
        }

        return {};
    }

}