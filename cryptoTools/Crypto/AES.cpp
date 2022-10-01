#include <cryptoTools/Crypto/AES.h>
#include <array>
#include <cstring>

#ifdef OC_ENABLE_AESNI
#include <wmmintrin.h>
#elif !defined(OC_ENABLE_PORTABLE_AES)
static_assert(0, "OC_ENABLE_PORTABLE_AES must be defined if ENABLE_AESNI is not.");
#endif

namespace osuCrypto {

    const AES mAesFixedKey(toBlock(45345336, -103343430));


    namespace details
    {

#ifdef OC_ENABLE_AESNI
        block keyGenHelper(block key, block keyRcon)
        {
            keyRcon = _mm_shuffle_epi32(keyRcon, _MM_SHUFFLE(3, 3, 3, 3));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
            return _mm_xor_si128(key, keyRcon);
        };



        template<>
        void AES<NI>::setKey(const block& userKey)
        {

            mRoundKey[0] = userKey;
            mRoundKey[1] = keyGenHelper(mRoundKey[0], _mm_aeskeygenassist_si128(mRoundKey[0], 0x01));
            mRoundKey[2] = keyGenHelper(mRoundKey[1], _mm_aeskeygenassist_si128(mRoundKey[1], 0x02));
            mRoundKey[3] = keyGenHelper(mRoundKey[2], _mm_aeskeygenassist_si128(mRoundKey[2], 0x04));
            mRoundKey[4] = keyGenHelper(mRoundKey[3], _mm_aeskeygenassist_si128(mRoundKey[3], 0x08));
            mRoundKey[5] = keyGenHelper(mRoundKey[4], _mm_aeskeygenassist_si128(mRoundKey[4], 0x10));
            mRoundKey[6] = keyGenHelper(mRoundKey[5], _mm_aeskeygenassist_si128(mRoundKey[5], 0x20));
            mRoundKey[7] = keyGenHelper(mRoundKey[6], _mm_aeskeygenassist_si128(mRoundKey[6], 0x40));
            mRoundKey[8] = keyGenHelper(mRoundKey[7], _mm_aeskeygenassist_si128(mRoundKey[7], 0x80));
            mRoundKey[9] = keyGenHelper(mRoundKey[8], _mm_aeskeygenassist_si128(mRoundKey[8], 0x1B));
            mRoundKey[10] = keyGenHelper(mRoundKey[9], _mm_aeskeygenassist_si128(mRoundKey[9], 0x36));
        }


#endif

#if defined(OC_ENABLE_PORTABLE_AES)
        // The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
        // The numbers below can be computed dynamically trading ROM for RAM -
        // This can be useful in (embedded) bootloader applications, where ROM is often limited.
        static const u8 sbox[256] = {
            //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

        static const u8 rsbox[256] = {
          0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
          0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
          0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
          0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
          0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
          0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
          0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
          0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
          0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
          0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
          0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
          0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
          0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
          0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
          0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
          0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };


        inline u8 getSBoxValue(int num) { return  sbox[num]; }
        inline u8 getSBoxInvert(int num) { return rsbox[num]; }

        static const uint8_t Rcon[AES<Portable>::rounds + 1] = {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

        // The number of columns comprising a state in AES. This is a constant in AES. Value=4
        //const u64 Nb = 4;
        //const u64 Nk = 4;        // The number of 32 bit words in a key.


        template<>
        void AES<Portable>::setKey(const block& userKey)
        {
            // This function produces 4(4+1) round keys. The round keys are used in each round to decrypt the states.
            auto RoundKey = (u8*)mRoundKey.data();
            auto Key = (const u8*)&userKey;

            unsigned i, j, k;
            uint8_t tempa[4]; // Used for the column/row operations

            // The first round key is the key itself.
            for (i = 0; i < 4; ++i)
            {
                RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
                RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
                RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
                RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
            }

            // All other round keys are found from the previous round keys.
            for (i = 4; i < 4 * (rounds + 1); ++i)
            {
                {
                    k = (i - 1) * 4;
                    tempa[0] = RoundKey[k + 0];
                    tempa[1] = RoundKey[k + 1];
                    tempa[2] = RoundKey[k + 2];
                    tempa[3] = RoundKey[k + 3];

                }

                if (i % 4 == 0)
                {
                    // This function shifts the 4 bytes in a word to the left once.
                    // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

                    // Function RotWord()
                    {
                        const uint8_t u8tmp = tempa[0];
                        tempa[0] = tempa[1];
                        tempa[1] = tempa[2];
                        tempa[2] = tempa[3];
                        tempa[3] = u8tmp;
                    }

                    // SubWord() is a function that takes a four-byte input word and
                    // applies the S-box to each of the four bytes to produce an output word.

                    // Function Subword()
                    {
                        tempa[0] = getSBoxValue(tempa[0]);
                        tempa[1] = getSBoxValue(tempa[1]);
                        tempa[2] = getSBoxValue(tempa[2]);
                        tempa[3] = getSBoxValue(tempa[3]);
                    }

                    tempa[0] = tempa[0] ^ Rcon[i / 4];
                }
                j = i * 4; k = (i - 4) * 4;
                RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
                RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
                RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
                RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
            }
        }


        std::array<std::array<u8, 4>, 4>& stateView(block& state)
        {
            return *(std::array<std::array<u8, 4>, 4>*) & state;
        }


        // The SubBytes Function Substitutes the values in the
        // state matrix with values in an S-box.
        inline void SubBytes(block& state_)
        {
            u8* state = state_.data();
            for (u64 i = 0; i < 16; ++i)
                state[i] = getSBoxValue(state[i]);
        }


        // The ShiftRows() function shifts the rows in the state to the left.
        // Each row is shifted with different offset.
        // Offset = Row number. So the first row is not shifted.
        inline void ShiftRows(block& state_)
        {
            uint8_t temp;
            auto& state = stateView(state_);

            // Rotate first row 1 columns to left
            temp = state[0][1];
            state[0][1] = state[1][1];
            state[1][1] = state[2][1];
            state[2][1] = state[3][1];
            state[3][1] = temp;

            // Rotate second row 2 columns to left
            temp = state[0][2];
            state[0][2] = state[2][2];
            state[2][2] = temp;

            temp = state[1][2];
            state[1][2] = state[3][2];
            state[3][2] = temp;

            // Rotate third row 3 columns to left
            temp = state[0][3];
            state[0][3] = state[3][3];
            state[3][3] = state[2][3];
            state[2][3] = state[1][3];
            state[1][3] = temp;
        }

        inline uint8_t xtime(uint8_t x)
        {
            return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
        }

        inline uint8_t Multiply(uint8_t x, uint8_t y)
        {
            return (((y & 1) * x) ^
                ((y >> 1 & 1)* xtime(x)) ^
                ((y >> 2 & 1)* xtime(xtime(x))) ^
                ((y >> 3 & 1)* xtime(xtime(xtime(x)))) ^
                ((y >> 4 & 1)* xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
        }

        // MixColumns function mixes the columns of the state matrix
        inline void MixColumns(block& state_)
        {
            auto& state = stateView(state_);
            uint8_t i;
            uint8_t Tmp, Tm, t;
            for (i = 0; i < 4; ++i)
            {
                t = state[i][0];
                Tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];
                Tm = state[i][0] ^ state[i][1]; Tm = xtime(Tm);  state[i][0] ^= Tm ^ Tmp;
                Tm = state[i][1] ^ state[i][2]; Tm = xtime(Tm);  state[i][1] ^= Tm ^ Tmp;
                Tm = state[i][2] ^ state[i][3]; Tm = xtime(Tm);  state[i][2] ^= Tm ^ Tmp;
                Tm = state[i][3] ^ t;           Tm = xtime(Tm);  state[i][3] ^= Tm ^ Tmp;
            }
        }


        template<>
        block AES<Portable>::roundEnc(block state, const block& roundKey)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            state = state ^ roundKey;
            return state;
        }

        template<>
        block AES<Portable>::finalEnc(block state, const block& roundKey)
        {
            SubBytes(state);
            ShiftRows(state);
            state = state ^ roundKey;
            return state;
        }
#endif

        template<AESTypes type>
        AES<type>::AES(const block& userKey)
        {
            setKey(userKey);
        }

        // Use templates for loop unrolling.
        template<AESTypes type, u64 step, u64 i = 0>
        static OC_FORCEINLINE typename std::enable_if<(i < step)>::type
        ctrModeEnd(const AES<type>& aes, block baseIdx, u64 misalignment,
                   block superBlock[step], u8* ciphertext)
        {
            if (misalignment > i)
            {
                superBlock[i] = baseIdx + toBlock(i);
                ctrModeEnd<type, step, i + 1>(
                    aes, baseIdx, misalignment, superBlock, ciphertext);
                memcpy(ciphertext + i * sizeof(block), superBlock + i, sizeof(block));
            }
            else
                aes.template ecbEncBlocks<i>(superBlock, superBlock);
        }

        // Base case
        template<AESTypes type, u64 step, u64 i = 0>
        static OC_FORCEINLINE typename std::enable_if<(i == step)>::type
        ctrModeEnd(const AES<type>& aes, block baseIdx, u64 misalignment,
                   block superBlock[step], u8* ciphertext) {}

        template<AESTypes type>
        void AES<type>::ecbEncCounterModeImpl(block baseIdx, u64 blockLength, u8* ciphertext) const
        {
            const i32 step = 8;
            u64 idx = 0;
            block superBlock[step], temp[step];

            for (; idx + step <= blockLength; idx += step)
            {
                for (i32 i = 0; i < step; ++i)
                    superBlock[i] = baseIdx + toBlock(i);
                baseIdx = baseIdx + toBlock(step);

                ecbEncBlocks<8>(superBlock, temp);
                memcpy(ciphertext, temp, sizeof(block) * step);
                ciphertext += sizeof(block) * step;
            }

            ctrModeEnd<type, step>(*this, baseIdx, blockLength % step, superBlock, ciphertext);
        }


#ifdef OC_ENABLE_AESNI
        template<>
        block AESDec<NI>::roundDec(block state, const block& roundKey)
        {
            return _mm_aesdec_si128(state, roundKey);
        }

        template<>
        block AESDec<NI>::finalDec(block state, const block& roundKey)
        {
            return _mm_aesdeclast_si128(state, roundKey);
        }


        template<>
        void AESDec<NI>::setKey(const block& userKey)
        {
            const block& v0 = userKey;
            const block  v1 = details::keyGenHelper(v0, _mm_aeskeygenassist_si128(v0, 0x01));
            const block  v2 = details::keyGenHelper(v1, _mm_aeskeygenassist_si128(v1, 0x02));
            const block  v3 = details::keyGenHelper(v2, _mm_aeskeygenassist_si128(v2, 0x04));
            const block  v4 = details::keyGenHelper(v3, _mm_aeskeygenassist_si128(v3, 0x08));
            const block  v5 = details::keyGenHelper(v4, _mm_aeskeygenassist_si128(v4, 0x10));
            const block  v6 = details::keyGenHelper(v5, _mm_aeskeygenassist_si128(v5, 0x20));
            const block  v7 = details::keyGenHelper(v6, _mm_aeskeygenassist_si128(v6, 0x40));
            const block  v8 = details::keyGenHelper(v7, _mm_aeskeygenassist_si128(v7, 0x80));
            const block  v9 = details::keyGenHelper(v8, _mm_aeskeygenassist_si128(v8, 0x1B));
            const block  v10 = details::keyGenHelper(v9, _mm_aeskeygenassist_si128(v9, 0x36));


            _mm_storeu_si128(&mRoundKey[0].m128i(), v10);
            _mm_storeu_si128(&mRoundKey[1].m128i(), _mm_aesimc_si128(v9));
            _mm_storeu_si128(&mRoundKey[2].m128i(), _mm_aesimc_si128(v8));
            _mm_storeu_si128(&mRoundKey[3].m128i(), _mm_aesimc_si128(v7));
            _mm_storeu_si128(&mRoundKey[4].m128i(), _mm_aesimc_si128(v6));
            _mm_storeu_si128(&mRoundKey[5].m128i(), _mm_aesimc_si128(v5));
            _mm_storeu_si128(&mRoundKey[6].m128i(), _mm_aesimc_si128(v4));
            _mm_storeu_si128(&mRoundKey[7].m128i(), _mm_aesimc_si128(v3));
            _mm_storeu_si128(&mRoundKey[8].m128i(), _mm_aesimc_si128(v2));
            _mm_storeu_si128(&mRoundKey[9].m128i(), _mm_aesimc_si128(v1));
            _mm_storeu_si128(&mRoundKey[10].m128i(), v0);

        }

#endif

#if defined(OC_ENABLE_PORTABLE_AES)

        // MixColumns function mixes the columns of the state matrix.
        // The method used to multiply may be difficult to understand for the inexperienced.
        // Please use the references to gain more information.
        static void InvMixColumns(block& state_)
        {

            auto& state = stateView(state_);
            int i;
            uint8_t a, b, c, d;
            for (i = 0; i < 4; ++i)
            {
                a = state[i][0];
                b = state[i][1];
                c = state[i][2];
                d = state[i][3];

                state[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
                state[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
                state[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
                state[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
            }
        }


        // The SubBytes Function Substitutes the values in the
        // state matrix with values in an S-box.
        static void InvSubBytes(block& state_)
        {
            u8* state = state_.data();
            for (auto i = 0; i < 16; ++i)
                state[i] = getSBoxInvert(state[i]);
        }

        static void InvShiftRows(block& state_)
        {
            uint8_t temp;
            auto& state = stateView(state_);

            // Rotate first row 1 columns to right
            temp = state[3][1];
            state[3][1] = state[2][1];
            state[2][1] = state[1][1];
            state[1][1] = state[0][1];
            state[0][1] = temp;

            // Rotate second row 2 columns to right
            temp = state[0][2];
            state[0][2] = state[2][2];
            state[2][2] = temp;

            temp = state[1][2];
            state[1][2] = state[3][2];
            state[3][2] = temp;

            // Rotate third row 3 columns to right
            temp = state[0][3];
            state[0][3] = state[1][3];
            state[1][3] = state[2][3];
            state[2][3] = state[3][3];
            state[3][3] = temp;
        }


        template<>
        block AESDec<Portable>::roundDec(block state, const block& roundKey)
        {
            InvShiftRows(state);
            InvSubBytes(state);
            state = state ^ roundKey;
            InvMixColumns(state);
            return state;
        }

        template<>
        block AESDec<Portable>::finalDec(block state, const block& roundKey)
        {
            InvShiftRows(state);
            InvSubBytes(state);
            state = state ^ roundKey;
            return state;
        }


        template<>
        void AESDec<Portable>::setKey(const block& userKey)
        {
            // same as enc but in reverse
            AES<Portable> aes;
            aes.setKey(userKey);
            std::copy(aes.mRoundKey.begin(), aes.mRoundKey.end(), mRoundKey.rbegin());
        }

        //void InvCipher(block& state, std::array<block,11>& RoundKey)
        //{
        //    uint8_t round = 0;

        //    // Add the First round key to the state before starting the rounds.
        //    //std::cout << "\ninv[0] " << state << " ^ " << RoundKey[10] << std::endl;
        //    state = state ^ RoundKey[10];

        //    // There will be Nr rounds.
        //    // The first Nr-1 rounds are identical.
        //    // These Nr rounds are executed in the loop below.
        //    // Last one without InvMixColumn()
        //    for (round = (10 - 1); ; --round)
        //    {
        //        std::cout << "\ninv["<<10-round<<"] " << state << " ^ " << RoundKey[round] << std::endl;

        //        InvShiftRows(state);
        //        InvSubBytes(state);
        //        state = state ^ RoundKey[round];
        //        if (round == 0) {
        //            break;
        //        }
        //        InvMixColumns(state);
        //    }

        //    std::cout << "\ninv[11] " << state << std::endl;


        //}

#endif

        template<AESTypes type>
        void AESDec<type>::ecbDecBlock(const block& ciphertext, block& plaintext)
        {

            //std::cout << "\ndec[0] " << ciphertext << " ^ " << mRoundKey[0] << std::endl;

            plaintext = ciphertext ^ mRoundKey[0];
            //std::cout << "dec[1] " << plaintext << " ^ " << mRoundKey[1] << std::endl;
            plaintext = roundDec(plaintext, mRoundKey[1]);
            //std::cout << "dec[2] " << plaintext << " ^ " << mRoundKey[2] << std::endl;
            plaintext = roundDec(plaintext, mRoundKey[2]);
            //std::cout << "dec[3] " << plaintext << " ^ " << mRoundKey[3] << std::endl;
            plaintext = roundDec(plaintext, mRoundKey[3]);
            //std::cout << "dec[4] " << plaintext << " ^ " << mRoundKey[4] << std::endl;
            plaintext = roundDec(plaintext, mRoundKey[4]);
            //std::cout << "dec[5] " << plaintext << " ^ " << mRoundKey[5] << std::endl;
            plaintext = roundDec(plaintext, mRoundKey[5]);
            //std::cout << "dec[6] " << plaintext << " ^ " << mRoundKey[6] << std::endl;
            plaintext = roundDec(plaintext, mRoundKey[6]);
            //std::cout << "dec[7] " << plaintext << " ^ " << mRoundKey[7] << std::endl;
            plaintext = roundDec(plaintext, mRoundKey[7]);
            //std::cout << "dec[8] " << plaintext << " ^ " << mRoundKey[8] << std::endl;
            plaintext = roundDec(plaintext, mRoundKey[8]);
            //std::cout << "dec[9] " << plaintext << " ^ " << mRoundKey[9] << std::endl;
            plaintext = roundDec(plaintext, mRoundKey[9]);
            //std::cout << "dec[10] " << plaintext << " ^ " << mRoundKey[10] << std::endl;
            plaintext = finalDec(plaintext, mRoundKey[10]);
            //std::cout << "dec[11] " << plaintext << std::endl;

        }
    }

#ifdef OC_ENABLE_PORTABLE_AES
    template class details::AES<details::Portable>;
    template class details::AESDec<details::Portable>;
#endif

#ifdef OC_ENABLE_AESNI
    template class details::AES<details::NI>;
    template class details::AESDec<details::NI>;
#endif


    void AESStream::setSeed(block seed)
    {
        mIndex = 0;
        mPrng.setKey(seed);
        refillBuffer();
    }
}
