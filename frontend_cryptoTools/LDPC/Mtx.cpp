#include "Mtx.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "LdpcSampler.h"

namespace osuCrypto
{
    void tests::Mtx_add_test()
    {

        u64 n1 = 20,
            n2 = 30;

        PRNG prng(block(0, 0));

        DenseMtx d1(n1, n2);
        DenseMtx d2(n1, n2);

        for (u64 i = 0; i < n1; ++i)
            for (u64 j = 0; j < n2; ++j)
            {
                d1(i, j) = prng.getBit();
                d2(i, j) = prng.getBit();
            }

        auto s1 = d1.sparse();
        auto s2 = d2.sparse();



        auto d3 = d1 + d2;
        auto s3 = s1 + s2;

        assert(s3 == d3.sparse());
        assert(d3 == s3.dense());
    }
    void tests::Mtx_mult_test()
    {
        u64 n1 = 20,
            n2 = 30,
            n3 = 40;

        PRNG prng(block(0, 0));

        DenseMtx d1(n1, n2);
        DenseMtx d2(n2, n3);

        for (u64 i = 0; i < n1; ++i)
            for (u64 j = 0; j < n2; ++j)
                d1(i, j) = prng.getBit();

        for (u64 i = 0; i < n2; ++i)
            for (u64 j = 0; j < n3; ++j)
                d2(i, j) = prng.getBit();

        auto s1 = d1.sparse();
        auto s2 = d2.sparse();



        auto d3 = d1 * d2;
        auto s3 = s1 * s2;

        assert(s3 == d3.sparse());
        assert(d3 == s3.dense());
    }

    void tests::Mtx_invert_test()
    {

        u64 n1 = 40;

        PRNG prng(block(0, 0));

        DenseMtx d1(n1, n1);

        for (u64 i = 0; i < n1; ++i)
            for (u64 j = 0; j < n1; ++j)
                d1(i, j) = prng.getBit();

        auto inv = d1.invert();

        auto I = d1 * inv;

        assert(I == DenseMtx::Identity(n1));

    }

    void tests::Mtx_block_test()
    {
        PRNG prng(block(0, 0));

        u64 n = 10, w = 4;
        auto n2 = n / 2;
        auto M = sampleFixedColWeight(n, n, w, prng);


        auto M00 = M.block(0 , 0 , n2, n2);
        auto M01 = M.block(0 , n2, n2, n2);
        auto M10 = M.block(n2, 0 , n2, n2);
        auto M11 = M.block(n2, n2, n2, n2);


        //std::cout << M << std::endl;
        //std::cout << M00 << std::endl;
        //std::cout << M01 << std::endl;
        //std::cout << M10 << std::endl;
        //std::cout << M11 << std::endl;


        u64 cc =
            M00.mDataCol.size() +
            M01.mDataCol.size() +
            M10.mDataCol.size() +
            M11.mDataCol.size() , 
            rr =
            M00.mDataRow.size() +
            M01.mDataRow.size() +
            M10.mDataRow.size() +
            M11.mDataRow.size();
        


        assert(cc == M.mDataCol.size());
        assert(rr == M.mDataRow.size());

        assert(M.validate());
        assert(M00.validate());
        assert(M01.validate());
        assert(M10.validate());
        assert(M11.validate());

        for (u64 i = 0; i < n2; ++i)
        {
            for (u64 j = 0; j < n2; ++j)
            {
                assert(M.isSet(i, j) == M00.isSet(i, j));
                assert(M.isSet(i, j + n2) == M01.isSet(i, j));
                assert(M.isSet(i + n2, j) == M10.isSet(i, j));
                assert(M.isSet(i + n2, j + n2) == M11.isSet(i, j));
            }
        }

    }

    

}