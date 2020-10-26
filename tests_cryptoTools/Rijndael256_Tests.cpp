//#include "stdafx.h"

#include <thread>
#include <vector>
#include <memory>

#include "Common.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Common/Log.h>

using namespace osuCrypto;

#include <iomanip>
namespace tests_cryptoTools
{
    template<details::Rijndael256Types type>
    void test()
    {
        using Block = typename details::Rijndael256Enc<type>::Block;

        const std::uint8_t userKeyArr[] = {
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
            0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48,
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
            0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48
        };
        const std::uint8_t ptxtArr[] = {
            0x2E, 0xCA, 0xB2, 0xAC, 0xDC, 0xCE, 0xE8, 0xBA,
            0x38, 0x58, 0xA3, 0x75, 0x0A, 0x2B, 0xFA, 0x5C,
            0xD8, 0x39, 0x39, 0x7B, 0x44, 0x5D, 0xBD, 0x93,
            0x67, 0x05, 0x21, 0x08, 0xF7, 0xD7, 0x54, 0x8E
        };
        const std::uint8_t expCtxtArr[] = {
            0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84,
            0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84,
            0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84,
            0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84
        };

        Block userKey = {toBlock(userKeyArr), toBlock(&userKeyArr[16])};
        Block ptxt = {toBlock(ptxtArr), toBlock(&ptxtArr[16])};
        Block expCtxt = {toBlock(expCtxtArr), toBlock(&expCtxtArr[16])};

        details::Rijndael256Enc<type> encKey(userKey);

        auto ctxt = encKey.encBlock(ptxt);
        if (ctxt != expCtxt)
            throw UnitTestFail();

        details::Rijndael256Dec<type> decKey(encKey);

        auto ptxt2 = decKey.decBlock(ctxt);
        if (ptxt2 != ptxt)
            throw UnitTestFail();

        u64 length = 1 << 10;

        std::vector<Block> data(length);
        std::vector<Block> cyphertext1(length);
        std::vector<Block> cyphertext2(length);

        for (u64 i = 0; i < length; ++i)
        {
            data[i] = {toBlock((std::uint64_t) 0), toBlock(i)};

            cyphertext1[i] = encKey.encBlock(data[i]);
            ptxt = decKey.decBlock(cyphertext1[i]);

            if (data[i] != ptxt)
                throw UnitTestFail();
        }

        // TODO: enc and dec multiple blocks.
        //encKey.encBlocks(data.data(), data.size(), cyphertext2.data());
        //
        //for (u64 i = 0; i < length; ++i)
        //{
        //    if (cyphertext1[i] != cyphertext2[i])
        //        throw UnitTestFail();
        //}
    }

    void Rijndael256_EncDec_Test()
    {
#ifdef OC_ENABLE_AESNI
        test<details::Rijndael256Types::NI>();
#endif // ENABLE_AESNI
#ifdef OC_ENABLE_PORTABLE_AES
        test<details::Rijndael256Types::Portable>();
#endif // ENABLE_PORTABLE_AES


    }

}
