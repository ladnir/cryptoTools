//#include "stdafx.h"

#include <cryptoTools/Common/Defines.h>
#ifdef OC_ENABLE_AESNI

#include <thread>
#include <vector>
#include <memory>

#include "Common.h"
#include <cryptoTools/Crypto/Rijndael256.h>
#include <cryptoTools/Common/Log.h>

using namespace osuCrypto;

#include <iomanip>
namespace tests_cryptoTools
{
    void Rijndael256_EncDec_Test()
    {
        using Block = typename Rijndael256Enc::Block;

        const std::uint8_t userKeyArr[] = {
            0x6e, 0x49, 0x0e, 0xe6, 0x2b, 0xa8, 0xf4, 0x0a,
            0x95, 0x83, 0xff, 0xa1, 0x59, 0xa5, 0x9d, 0x33,
            0x1d, 0xa6, 0x15, 0xcd, 0x1e, 0x8c, 0x75, 0xe1,
            0xea, 0xe3, 0x35, 0xe4, 0x76, 0xed, 0xf1, 0xdf,
        };
        const std::uint8_t ptxtArr[] = {
            0x79, 0xfd, 0x3f, 0xf6, 0x5b, 0xa2, 0xfd, 0x26,
            0x4d, 0xb4, 0x8a, 0xe6, 0x89, 0x07, 0x52, 0x25,
            0x05, 0xa4, 0xa7, 0x83, 0xd7, 0xea, 0xe8, 0x27,
            0xec, 0xb5, 0x3e, 0x5e, 0x76, 0x3d, 0x30, 0x37,
        };
        const std::uint8_t expCtxtArr[] = {
            0x25, 0x8d, 0xa5, 0xeb, 0xce, 0xf2, 0x4a, 0xa7,
            0x41, 0xb5, 0xa2, 0xa0, 0x78, 0x86, 0x59, 0xfc,
            0x0a, 0xcc, 0x3d, 0x25, 0x66, 0x58, 0x4f, 0xb6,
            0x4d, 0xda, 0xef, 0x25, 0xc1, 0xcd, 0xe0, 0xee,
        };

        Block userKey = Block256(userKeyArr);
        Block ptxt = Block256(ptxtArr);
        Block expCtxt = Block256(expCtxtArr);

        Rijndael256Enc encKey(userKey);

        auto ctxt = encKey.encBlock(ptxt);
        if (ctxt != expCtxt)
            throw UnitTestFail();

        Rijndael256Dec decKey(encKey);

        auto ptxt2 = decKey.decBlock(ctxt);
        if (ptxt2 != ptxt)
            throw UnitTestFail();

        size_t length = 1 << 10;

        std::vector<Block> data(length);
        std::vector<Block> ciphertext1(length);
        std::vector<Block> ciphertext2(length);

        for (size_t i = 0; i < length; ++i)
        {
            data[i] = Block256(i);

            ciphertext1[i] = encKey.encBlock(data[i]);
            ptxt = decKey.decBlock(ciphertext1[i]);

            if (data[i] != ptxt)
                throw UnitTestFail();
        }

        encKey.encBlocks(data.data(), data.size(), ciphertext2.data());

        for (size_t i = 0; i < length; ++i)
            if (ciphertext1[i] != ciphertext2[i])
                throw UnitTestFail();

        std::vector<Block> plaintext = std::move(ciphertext2);
        decKey.decBlocks(ciphertext1.data(), ciphertext1.size(), plaintext.data());

        for (size_t i = 0; i < length; ++i)
            if (data[i] != plaintext[i])
                throw UnitTestFail();
    }
}

#endif // ENABLE_AESNI
