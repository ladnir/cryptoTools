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
        auto Rijndael256Enc<NI>::roundEnc(Block state, const Block& roundKey) -> Block
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
        auto Rijndael256Enc<NI>::finalEnc(Block state, const Block& roundKey) -> Block
        {
            __m128i b0 = state[0];
            __m128i b1 = state[1];

            rotateRows256Undo128<true>(b0, b1);
            b0 = _mm_aesenclast_si128(b0, roundKey[0]);
            b1 = _mm_aesenclast_si128(b1, roundKey[1]);

            return {b0, b1};
        }

        template<>
        auto Rijndael256Dec<NI>::roundDec(Block state, const Block& roundKey) -> Block
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
        auto Rijndael256Dec<NI>::finalDec(Block state, const Block& roundKey) -> Block
        {
            __m128i b0 = state[0];
            __m128i b1 = state[1];

            rotateRows256Undo128<false>(b0, b1);
            b0 = _mm_aesdeclast_si128(b0, roundKey[0]);
            b1 = _mm_aesdeclast_si128(b1, roundKey[1]);

            return {b0, b1};
        }

        template<>
        auto Rijndael256Enc<NI>::encBlock(Block block) const -> Block {
            //__m128i b0 = block[0];
            //__m128i b1 = block[1];

            //b0 = _mm_xor_si128(b0, mRoundKey[0][0]);
            //b1 = _mm_xor_si128(b1, mRoundKey[0][1]);
            //Block b = block;

            block[0] = _mm_xor_si128(block[0], mRoundKey[0][0]);
            block[1] = _mm_xor_si128(block[1], mRoundKey[0][1]);

            for (int i = 1; i < rounds; ++i) {
                block = roundEnc(block, mRoundKey[i]);

                //rotateRows256Undo128<true>(b0, b1);

                //// Use the AES round function to implement the Rijndael256 round function.
                //if (i < rounds)
                //{
                //    b0 = _mm_aesenc_si128(b0, mRoundKey[i][0]);
                //    b1 = _mm_aesenc_si128(b1, mRoundKey[i + 1][1]);
                //}
                //else
                //{
                //    b0 = _mm_aesenclast_si128(b0, mRoundKey[rounds][0]);
                //    b1 = _mm_aesenclast_si128(b1, mRoundKey[rounds][1]);
                //}
            }

            block = finalEnc(block, mRoundKey[rounds]);

            //block[0] = b0;
            //block[1] = b1;

            return block;
        }

        template<>
        auto Rijndael256Dec<NI>::decBlock(Block block) const -> Block {
            //__m128i b0 = block[0];
            //__m128i b1 = block[1];

            //b0 = _mm_xor_si128(b0, mRoundKey[rounds]0]);
            //b1 = _mm_xor_si128(b1, mRoundKey[rounds]1]);
            //Block b = block;

            block[0] = _mm_xor_si128(block[0], mRoundKey[rounds][0]);
            block[1] = _mm_xor_si128(block[1], mRoundKey[rounds][1]);

            for (int i = rounds - 1; i > 0; --i) {
                block = roundDec(block, mRoundKey[i]);

                //rotateRows256Undo128<false>(b0, b1);

                //// Use the AES round function to implement the Rijndael256 round function.
                //if (i > 0)
                //{
                //    b0 = _mm_aesdec_si128(b0, mRoundKey[i][0]);
                //    b1 = _mm_aesdec_si128(b1, mRoundKey[i + 1][1]);
                //}
                //else
                //{
                //    b0 = _mm_aesdeclast_si128(b0, mRoundKey[rounds][0]);
                //    b1 = _mm_aesdeclast_si128(b1, mRoundKey[rounds][1]);
                //}
            }

            block = finalDec(block, mRoundKey[0]);

            //block[0] = b0;
            //block[1] = b1;

            return block;
        }

        static inline void expandRound(
            std::array<Rijndael256Enc<NI>::Block, Rijndael256Enc<NI>::rounds + 1>& roundKeys,
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
        void Rijndael256Enc<NI>::setKey(const Block& userKey)
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
        void Rijndael256Dec<NI>::setKey(const Rijndael256Enc<NI>& enc)
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
    template class details::Rijndael256Enc<details::NI>;
    template class details::Rijndael256Dec<details::NI>;
#endif
// TODO: if defined(OC_ENABLE_PORTABLE_AES)
}
