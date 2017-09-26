#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>
#define AES_DECRYPTION
#include <wmmintrin.h>

namespace osuCrypto {

#define AES_BLK_SIZE 16




    class AES
    {
    public:

        AES();
        AES(const block& userKey);


        void setKey(const block& userKey);


        void ecbEncBlock(const block& plaintext, block& cyphertext) const;
        block ecbEncBlock(const block& plaintext) const;

        void ecbEncBlocks(const block* plaintexts, u64 blockLength, block* cyphertext) const;

        void ecbEncTwoBlocks(const block* plaintexts, block* cyphertext) const;
        void ecbEncFourBlocks(const block* plaintexts, block* cyphertext) const;
        void ecbEnc16Blocks(const block* plaintexts, block* cyphertext) const;


        void ecbEncCounterMode(u64 baseIdx, u64 longth, block* cyphertext);
        //void ecbEncCounterMode(u64 baseIdx, u64 longth, block* cyphertext, const u64* destIdxs);

        block mRoundKey[11];
    };

    template<int N>
    class MultiKeyAES
    {
    public:
        std::array<AES, N> mAESs;

        MultiKeyAES() {};
        MultiKeyAES(span<block> keys)
        {
            setKeys(keys);
        }

        void setKeys(span<block> keys)
        {
            for (u64 i = 0; i < N; ++i)
            {
                mAESs[i].setKey(keys[i]);
            }
        }

        void ecbEncNBlocks(const block* plaintext, block* cyphertext) const
        {

            OSU_CRYPTO_COMPILER_UNROLL_LOOP_HINT
                for (int i = 0; i < N; ++i) cyphertext[i] = _mm_xor_si128(plaintext[i], mAESs[i].mRoundKey[0]);
            OSU_CRYPTO_COMPILER_UNROLL_LOOP_HINT
                for (int i = 0; i < N; ++i) cyphertext[i] = _mm_aesenc_si128(cyphertext[i], mAESs[i].mRoundKey[1]);
            OSU_CRYPTO_COMPILER_UNROLL_LOOP_HINT
                for (int i = 0; i < N; ++i) cyphertext[i] = _mm_aesenc_si128(cyphertext[i], mAESs[i].mRoundKey[2]);
            OSU_CRYPTO_COMPILER_UNROLL_LOOP_HINT
                for (int i = 0; i < N; ++i) cyphertext[i] = _mm_aesenc_si128(cyphertext[i], mAESs[i].mRoundKey[3]);
            OSU_CRYPTO_COMPILER_UNROLL_LOOP_HINT
                for (int i = 0; i < N; ++i) cyphertext[i] = _mm_aesenc_si128(cyphertext[i], mAESs[i].mRoundKey[4]);
            OSU_CRYPTO_COMPILER_UNROLL_LOOP_HINT
                for (int i = 0; i < N; ++i) cyphertext[i] = _mm_aesenc_si128(cyphertext[i], mAESs[i].mRoundKey[5]);
            OSU_CRYPTO_COMPILER_UNROLL_LOOP_HINT
                for (int i = 0; i < N; ++i) cyphertext[i] = _mm_aesenc_si128(cyphertext[i], mAESs[i].mRoundKey[6]);
            OSU_CRYPTO_COMPILER_UNROLL_LOOP_HINT
                for (int i = 0; i < N; ++i) cyphertext[i] = _mm_aesenc_si128(cyphertext[i], mAESs[i].mRoundKey[7]);
            OSU_CRYPTO_COMPILER_UNROLL_LOOP_HINT
                for (int i = 0; i < N; ++i) cyphertext[i] = _mm_aesenc_si128(cyphertext[i], mAESs[i].mRoundKey[8]);
            OSU_CRYPTO_COMPILER_UNROLL_LOOP_HINT
                for (int i = 0; i < N; ++i) cyphertext[i] = _mm_aesenc_si128(cyphertext[i], mAESs[i].mRoundKey[9]);
            OSU_CRYPTO_COMPILER_UNROLL_LOOP_HINT
                for (int i = 0; i < N; ++i) cyphertext[i] = _mm_aesenclast_si128(cyphertext[i], mAESs[i].mRoundKey[10]);
        }


        const MultiKeyAES<N>& operator=(const MultiKeyAES<N>& rhs)
        {
            for (u64 i = 0; i < N; ++i)
                memcpy(mAESs[i].mRoundKey, rhs.mAESs[i].mRoundKey, sizeof(block) * 11);

            return rhs;
        }
    };

    extern     const AES mAesFixedKey;

    class AESDec
    {
    public:

        AESDec();
        AESDec(const block& userKey);

        void setKey(const block& userKey);

        void ecbDecBlock(const block& cyphertext, block& plaintext);
        block ecbDecBlock(const block& cyphertext);
        block mRoundKey[11];
    };

}
