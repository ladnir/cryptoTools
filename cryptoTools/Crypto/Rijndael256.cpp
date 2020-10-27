#include <cryptoTools/Crypto/Rijndael256.h>
#include <array>

#ifdef OC_ENABLE_AESNI
#include <wmmintrin.h>
#elif !defined(OC_ENABLE_PORTABLE_AES)
static_assert(0, "OC_ENABLE_PORTABLE_AES must be defined if ENABLE_AESNI is not.");
#endif

namespace osuCrypto {
    namespace details
    {
#ifdef OC_ENABLE_AESNI
        // This implement's Rijndael256 RotateRows step, then cancels out the RotateRows of AES so
        // that AES-NI can be used to implement Rijndael256.
        template<bool encrypt>
        static inline void rotateRows256Undo128(__m128i& b0, __m128i& b1) {
            // Swapping bytes between 128-bit halves is equivalent to rotating left overall, then
            // rotating right within each half. Decrypt is the same idea, but with reverse shifts.
            __m128i mask;
            if (encrypt)
            {
                mask = _mm_setr_epi8(0, -1, -1, -1,
                                     0,  0, -1, -1,
                                     0,  0, -1, -1,
                                     0,  0,  0, -1);
            }
            else
            {
                mask = _mm_setr_epi8(0,  0,  0, -1,
                                     0,  0, -1, -1,
                                     0,  0, -1, -1,
                                     0, -1, -1, -1);
            }
            __m128i b0_blended = _mm_blendv_epi8(b0, b1, mask);
            __m128i b1_blended = _mm_blendv_epi8(b1, b0, mask);

            // The rotations for 128-bit AES are different, so rotate within the halves to
            // match.
            __m128i perm;
            if (encrypt)
            {
                perm = _mm_setr_epi8( 0,  1,  6,  7,
                                      4,  5, 10, 11,
                                      8,  9, 14, 15,
                                     12, 13,  2,  3);
            }
            else
            {
                perm = _mm_setr_epi8( 0,  1, 14, 15,
                                      4,  5,  2,  3,
                                      8,  9,  6,  7,
                                     12, 13, 10, 11);
            }
            b0 = _mm_shuffle_epi8(b0_blended, perm);
            b1 = _mm_shuffle_epi8(b1_blended, perm);
        }

        template<>
        auto Rijndael256Enc<Rijndael256Types::NI>::roundEnc(Block state, const Block& roundKey) -> Block
        {
            __m128i b0 = state[0];
            __m128i b1 = state[1];

            // Use the AES round function to implement the Rijndael256 round function.
            rotateRows256Undo128<true>(b0, b1);
            b0 = _mm_aesenc_si128(b0, roundKey[0]);
            b1 = _mm_aesenc_si128(b1, roundKey[1]);

            return {b0, b1};
        }

        template<>
        auto Rijndael256Enc<Rijndael256Types::NI>::finalEnc(Block state, const Block& roundKey) -> Block
        {
            __m128i b0 = state[0];
            __m128i b1 = state[1];

            rotateRows256Undo128<true>(b0, b1);
            b0 = _mm_aesenclast_si128(b0, roundKey[0]);
            b1 = _mm_aesenclast_si128(b1, roundKey[1]);

            return {b0, b1};
        }

        template<>
        auto Rijndael256Dec<Rijndael256Types::NI>::roundDec(Block state, const Block& roundKey) -> Block
        {
            __m128i b0 = state[0];
            __m128i b1 = state[1];

            // Use the AES round function to implement the Rijndael256 round function.
            rotateRows256Undo128<false>(b0, b1);
            b0 = _mm_aesdec_si128(b0, roundKey[0]);
            b1 = _mm_aesdec_si128(b1, roundKey[1]);

            return {b0, b1};
        }

        template<>
        auto Rijndael256Dec<Rijndael256Types::NI>::finalDec(Block state, const Block& roundKey) -> Block
        {
            __m128i b0 = state[0];
            __m128i b1 = state[1];

            rotateRows256Undo128<false>(b0, b1);
            b0 = _mm_aesdeclast_si128(b0, roundKey[0]);
            b1 = _mm_aesdeclast_si128(b1, roundKey[1]);

            return {b0, b1};
        }

        template<> template<size_t numBlocks>
        void Rijndael256Enc<Rijndael256Types::NI>::encBlocksFixed(const Block* plaintext, Block* ciphertext) const
        {
            Block blocks[numBlocks];
            for (size_t j = 0; j < numBlocks; ++j)
            {
                blocks[j][0] = _mm_xor_si128(plaintext[j][0], mRoundKey[0][0]);
                blocks[j][1] = _mm_xor_si128(plaintext[j][1], mRoundKey[0][1]);
            }

            // Each iteration depends on the previous, so unrolling the outer loop isn't useful,
            // especially because there are a decent number of operations in each iteration.
            // TODO: Benchmark
            #pragma GCC unroll 1
            for (int i = 1; i < rounds; ++i)
                for (size_t j = 0; j < numBlocks; ++j)
                    blocks[j] = roundEnc(blocks[j], mRoundKey[i]);

            for (size_t j = 0; j < numBlocks; ++j)
                ciphertext[j] = finalEnc(blocks[j], mRoundKey[rounds]);
        }

        template<>
        void Rijndael256Enc<Rijndael256Types::NI>::encBlocks(
            const Block* plaintexts, size_t blocks, Block* ciphertext) const
        {
            constexpr size_t step = 4;
            size_t misalignment = blocks % step;
            size_t alignedLength = blocks - misalignment;

            for (size_t i = 0; i < alignedLength; i += step)
                encBlocksFixed<step>(plaintexts + i, ciphertext + i);

            switch (misalignment) {
            case 0:
                break;
            case 1:
                encBlocksFixed<1>(plaintexts + alignedLength, ciphertext + alignedLength);
                break;
            case 2:
                encBlocksFixed<2>(plaintexts + alignedLength, ciphertext + alignedLength);
                break;
            case 3:
                encBlocksFixed<3>(plaintexts + alignedLength, ciphertext + alignedLength);
                break;
            }
        }

        template<> template<size_t numBlocks>
        void Rijndael256Dec<Rijndael256Types::NI>::decBlocksFixed(const Block* ciphertext, Block* plaintext) const
        {
            Block blocks[numBlocks];
            for (size_t j = 0; j < numBlocks; ++j)
            {
                blocks[j][0] = _mm_xor_si128(ciphertext[j][0], mRoundKey[rounds][0]);
                blocks[j][1] = _mm_xor_si128(ciphertext[j][1], mRoundKey[rounds][1]);
            }

            // Each iteration depends on the previous, so unrolling the outer loop isn't useful,
            // especially because there are a decent number of operations in each iteration.
            #pragma GCC unroll 1
            for (int i = rounds - 1; i > 0; --i)
                for (size_t j = 0; j < numBlocks; ++j)
                    blocks[j] = roundDec(blocks[j], mRoundKey[i]);

            for (size_t j = 0; j < numBlocks; ++j)
                plaintext[j] = finalDec(blocks[j], mRoundKey[0]);
        }

        template<>
        void Rijndael256Dec<Rijndael256Types::NI>::decBlocks(
            const Block* ciphertexts, size_t blocks, Block* plaintext) const
        {
            constexpr size_t step = 4;
            size_t misalignment = blocks % step;
            size_t alignedLength = blocks - misalignment;

            for (size_t i = 0; i < alignedLength; i += step)
                decBlocksFixed<step>(ciphertexts + i, plaintext + i);

            switch (misalignment) {
            case 0:
                break;
            case 1:
                decBlocksFixed<1>(ciphertexts + alignedLength, plaintext + alignedLength);
                break;
            case 2:
                decBlocksFixed<2>(ciphertexts + alignedLength, plaintext + alignedLength);
                break;
            case 3:
                decBlocksFixed<3>(ciphertexts + alignedLength, plaintext + alignedLength);
                break;
            }
        }

        static inline void expandRound(
            std::array<Rijndael256Enc<Rijndael256Types::NI>::Block, Rijndael256Enc<Rijndael256Types::NI>::rounds + 1>& roundKeys,
            unsigned int round, unsigned char round_cosntant)
        {
            __m128i t1 = roundKeys[round - 1][0];
            __m128i t2;
            __m128i t3 = roundKeys[round - 1][1];
            __m128i t4;

            t2 = _mm_aeskeygenassist_si128(t3, round_cosntant);
            t2 = _mm_shuffle_epi32(t2, 0xff);
            t4 = _mm_slli_si128(t1, 0x4);
            t1 = _mm_xor_si128(t1, t4);
            t4 = _mm_slli_si128(t4, 0x4);
            t1 = _mm_xor_si128(t1, t4);
            t4 = _mm_slli_si128(t4, 0x4);
            t1 = _mm_xor_si128(t1, t4);
            t1 = _mm_xor_si128(t1, t2);

            roundKeys[round][0] = t1;

            t4 = _mm_aeskeygenassist_si128(t1, 0x00);
            t2 = _mm_shuffle_epi32(t4, 0xaa);
            t4 = _mm_slli_si128(t3, 0x4);
            t3 = _mm_xor_si128(t3, t4);
            t4 = _mm_slli_si128(t4, 0x4);
            t3 = _mm_xor_si128(t3, t4);
            t4 = _mm_slli_si128(t4, 0x4);
            t3 = _mm_xor_si128(t3, t4);
            t3 = _mm_xor_si128(t3, t2);

            roundKeys[round][1] = t3;
        };

        template<>
        void Rijndael256Enc<Rijndael256Types::NI>::setKey(const Block& userKey)
        {
            mRoundKey[0] = userKey;
            expandRound(mRoundKey, 1, 0x01);
            expandRound(mRoundKey, 2, 0x02);
            expandRound(mRoundKey, 3, 0x04);
            expandRound(mRoundKey, 4, 0x08);
            expandRound(mRoundKey, 5, 0x10);
            expandRound(mRoundKey, 6, 0x20);
            expandRound(mRoundKey, 7, 0x40);
            expandRound(mRoundKey, 8, 0x80);
            expandRound(mRoundKey, 9, 0x1B);
            expandRound(mRoundKey, 10, 0x36);
            expandRound(mRoundKey, 11, 0x6C);
            expandRound(mRoundKey, 12, 0xD8);
            expandRound(mRoundKey, 13, 0xAB);
            expandRound(mRoundKey, 14, 0x4D);
        }

        template<>
        void Rijndael256Dec<Rijndael256Types::NI>::setKey(const Rijndael256Enc<Rijndael256Types::NI>& enc)
        {
            mRoundKey[0] = enc.mRoundKey[0];
            for (int i = 1; i < rounds; i++)
                for (int j = 0; j < 2; j++)
                    mRoundKey[i][j] = _mm_aesimc_si128(enc.mRoundKey[i][j]);
            mRoundKey[rounds] = enc.mRoundKey[rounds];
        }
#endif

// TODO: if defined(OC_ENABLE_PORTABLE_AES)
    }

#ifdef OC_ENABLE_AESNI
    template class details::Rijndael256Enc<details::Rijndael256Types::NI>;
    template class details::Rijndael256Dec<details::Rijndael256Types::NI>;
#endif
// TODO: if defined(OC_ENABLE_PORTABLE_AES)

    template void Rijndael256Enc::encBlocksFixed<1>(const Block*, Block*) const;
    template void Rijndael256Enc::encBlocksFixed<2>(const Block*, Block*) const;
    template void Rijndael256Enc::encBlocksFixed<3>(const Block*, Block*) const;
    template void Rijndael256Enc::encBlocksFixed<4>(const Block*, Block*) const;
    template void Rijndael256Dec::decBlocksFixed<1>(const Block*, Block*) const;
    template void Rijndael256Dec::decBlocksFixed<2>(const Block*, Block*) const;
    template void Rijndael256Dec::decBlocksFixed<3>(const Block*, Block*) const;
    template void Rijndael256Dec::decBlocksFixed<4>(const Block*, Block*) const;
}
