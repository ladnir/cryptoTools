//#include "stdafx.h"

#include <thread>
#include <vector>
#include <memory>

#include "Common.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/AES.h> 
#include <cryptoTools/Common/Log.h>

using namespace osuCrypto;

//namespace tests_cryptoTools
//{
#include <iomanip>
namespace tests_cryptoTools
{
    block byteReverse(block b)
    {
        block r;
        auto bb = b.data();
        auto rr = r.data();
        for (u64 i = 0; i < 16; ++i)
            rr[i] = bb[15 - i];
        return r;
    }

    template<details::AESTypes type>
    void test()
    {

        block userKey = byteReverse(toBlock(
            0x0001020304050607,
            0x08090a0b0c0d0e0f));
        block ptxt = byteReverse(toBlock(
            0x0011223344556677,
            0x8899aabbccddeeff));
        block exp = byteReverse(toBlock(
            0x69c4e0d86a7b0430,
            0xd8cdb78070b4c55a));

        details::AES<type> encKey(userKey);
        //details::AES<details::Portable> encKey2(userKey);

        auto ctxt = encKey.ecbEncBlock(ptxt);
        if (neq(ctxt, exp))
            throw UnitTestFail();

        details::AESDec<type> decKey(userKey);

        auto ptxt2 = decKey.ecbDecBlock(ctxt);
        if (neq(ptxt2, ptxt))
            throw UnitTestFail();

        u64 length = 1 << 4;

        std::vector<block> data(length);
        std::vector<block> cyphertext1(length);
        std::vector<block> cyphertext2(length);

        for (u64 i = 0; i < length; ++i)
        {
            data[i] = toBlock(i);
            //block ptxt; , itxt;

            encKey.ecbEncBlock(data[i], cyphertext1[i]);

            decKey.ecbDecBlock(cyphertext1[i], ptxt);

            //itxt = cyphertext1[i];
            //details::InvCipher(itxt, encKey2.mRoundKey);

            //if (neq(data[i], plaintext[i]))
            //    throw UnitTestFail();

            if (neq(data[i], ptxt))
                throw UnitTestFail();
        }

        encKey.ecbEncBlocks(data.data(), data.size(), cyphertext2.data());

        for (u64 i = 0; i < length; ++i)
        {
            if (neq(cyphertext1[i], cyphertext2[i]))
                throw UnitTestFail();
        }


        u64 step = 3;
        std::vector<block> data2(length * step);
        for (u64 i = 0; i < length; ++i)
        {
            for (u64 j = 0; j < step; ++j)
            {
                data2[i * step + j] = block(45233453 * i, 234235543 * j);
            }

            data[i] = data2[i * step + (i % step)];
        }

        encKey.TmmoHashBlocks(data, cyphertext1, [t = 0]() mutable {return block(t++); });
        encKey.TmmoHashBlocks(data, cyphertext2, [t = 0]() mutable {return block(t++); });

        for (u64 i = 0; i < length; ++i)
        {

            if (cyphertext1[i] != cyphertext2[i])
            {
                throw RTE_LOC;
            }

            // y_i = AES(AES(x_i) ^ tweak_i) + AES(x_i).
            if (cyphertext1[i] != (encKey.ecbEncBlock(encKey.ecbEncBlock(data[i]) ^ block(i)) ^ encKey.ecbEncBlock(data[i])))
                throw RTE_LOC;

            if (cyphertext1[i] != encKey.TmmoHashBlock(data[i], block(i)))
                throw RTE_LOC;


        }

        cyphertext2.resize(data2.size());
        encKey.TmmoHashBlocks(data2, cyphertext2, [t = 0, step]() mutable {return block(t++ / step); });

        for (u64 i = 0; i < length; ++i)
        {

            if (cyphertext1[i] != cyphertext2[i * step + (i % step)])
            {
                throw RTE_LOC;
            }
        }
    }

    void AES_EncDec_Test()
    {
#ifdef OC_ENABLE_AESNI
        test<details::AESTypes::NI>();
#endif // ENABLE_SSE
#ifdef OC_ENABLE_PORTABLE_AES
        test<details::AESTypes::Portable>();
#endif // ENABLE_PORTABLE_AES


    }

}
