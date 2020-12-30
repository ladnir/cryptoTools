#pragma once
#include "Mtx.h"

namespace osuCrypto
{

    class DiagInverter
    {
    public:

        const SparseMtx* mC = nullptr;

        DiagInverter() = default;
        DiagInverter(const DiagInverter&) = default;
        DiagInverter& operator=(const DiagInverter&) = default;

        DiagInverter(const SparseMtx& c)
        {
            init(c);
        }
        void init(const SparseMtx& c)
        {
            mC = (&c);
            assert(mC->rows() == mC->cols());

#ifndef NDEBUG
            for (u64 i = 0; i < mC->rows(); ++i)
            {
                auto row = mC->row(i);
                assert(row.size() && row[row.size() - 1] == i);

                for (u64 j = 0; j < row.size() - 1; ++j)
                {
                    assert(row[j] < row[j + 1]);
                }
            }
#endif
        }


        // computes x = mC^-1 * y
        void mult(span<const u8> y, span<u8> x);

        // computes x = mC^-1 * y
        void mult(const SparseMtx& y, SparseMtx& x);

    };

    class LdpcEncoder
    {
    public:

        //using SparseMtx = std::vector<std::array<u64, 2>>;

        LdpcEncoder() = default;
        LdpcEncoder(const LdpcEncoder&) = default;
        LdpcEncoder(LdpcEncoder&&) = default;


        u64 mN, mM, mGap;
        SparseMtx mA, mH;
        SparseMtx mB;
        SparseMtx mC;
        SparseMtx mD;
        SparseMtx mE, mEp;
        SparseMtx mF;
        DiagInverter mCInv;


        bool init(SparseMtx mtx, u64 gap);


        void encode(span<u8> c, span<const u8> m);



    };


    namespace tests
    {

        void LdpcEncoder_diagonalSolver_test();
        void LdpcEncoder_encode_test();

    }

}