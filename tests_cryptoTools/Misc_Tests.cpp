#include "Misc_Tests.h"

#include <cryptoTools/Common/BitVector.h>
#include "Common.h"

using namespace osuCrypto;

namespace tests_cryptoTools
{
    void BitVector_Indexing_Test_Impl()
    {
        BitVector bb(128);
        std::vector<bool>gold(128);


        for (u64 i : std::vector<u64>{ { 2,33,34,26,85,33,99,12,126 } })
        {
            bb[i] = gold[i] = true;
        }


        for (auto i = 0; i < 128; ++i)
        {
            if ((bb[i] > 0) != gold[i])
                throw std::runtime_error("");

            if ((bb[i] > 0) != gold[i])
                throw UnitTestFail();
        }
    }

    void BitVector_Parity_Test_Impl()
    {
        PRNG prng(ZeroBlock);
        for (u64 i = 0; i < 100; ++i)
        {
            u8 size = prng.get<u8>();
            u8 parity = 0;
            u64 sum = 0;
            BitVector bv(size);

            bv.randomize(prng);

            for (u64 j = 0; j < size; ++j)
            {
                parity ^= bv[j];
                sum += bv[j];
            }

            if (sum != bv.hammingWeight())
                throw UnitTestFail();

            if (parity != bv.parity())
                throw UnitTestFail();
        }

    }

    void BitVector_Append_Test_Impl()
    {

        BitVector bv0(3);
        BitVector bv1(6);
        BitVector bv2(9);
        BitVector bv4;


        bv0[0] = 1; bv2[0] = 1;
        bv0[2] = 1; bv2[2] = 1;
        bv1[2] = 1; bv2[3 + 2] = 1;
        bv1[5] = 1; bv2[3 + 5] = 1;

        bv4.append(bv0);
        bv4.append(bv1);

        //std::cout << bv0 << bv1 << std::endl;
        //std::cout << bv2 << std::endl;
        //std::cout << bv4 << std::endl;

        if (bv4 != bv2)
            throw UnitTestFail();
    }


    void BitVector_Copy_Test_Impl()
    {
        u64 offset = 3;
        BitVector bb(128), c(128 - offset);


        for (u64 i : std::vector<u64>{ { 2,33,34,26,85,33,99,12,126 } })
        {
            bb[i] = true;
        }

        c.copy(bb, offset, 128 - offset);


        ////std::cout << "bb ";// << bb << Logger::endl;
        //for (u64 i = 0; i < bb.size(); ++i)
        //{
        //    if (bb[i]) std::cout << "1";
        //    else std::cout << "0";

        //}
        //std::cout << std::endl;
        //std::cout << "c   ";
        //for (u64 i = 0; i < c.size(); ++i)
        //{
        //    if (c[i]) std::cout << "1";
        //    else std::cout << "0";

        //}
        //std::cout << std::endl;

        for (u64 i = 0; i < 128 - offset; ++i)
        {
            if (bb[i + offset] != c[i])
                throw std::runtime_error("");

        }
    }

    void BitVector_Resize_Test_Impl()
    {
        u64 size0 = 9;
        BitVector bb(size0);

        u64 size1 = 11;
        bb.resize(size1, 1);

        u64 size2 = 13;
        bb.resize(size2, 0);

        u64 size3 = 31;
        bb.resize(size3, 1);

        for (u64 i{ 0 }; i < size0; ++i)
            if (bb[i])throw std::runtime_error(LOCATION);

        for (u64 i{ size0 }; i < size1; ++i)
            if (!bb[i])throw std::runtime_error(LOCATION);

        for (u64 i{ size1 }; i < size2; ++i)
            if (bb[i])throw std::runtime_error(LOCATION);

        for (u64 i{ size2 }; i < size3; ++i)
            if (!bb[i])throw std::runtime_error(LOCATION);


    }
}
