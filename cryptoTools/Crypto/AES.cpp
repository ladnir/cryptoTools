#include <cryptoTools/Crypto/AES.h>
#include <array>
#include <cstring>

#ifdef OC_ENABLE_AESNI
#include <wmmintrin.h>
#elif !defined(OC_ENABLE_PORTABLE_AES) && !defined(ENABLE_ARM_AES)
static_assert(0, "OC_ENABLE_PORTABLE_AES must be defined if ENABLE_AESNI and ENABLE_ARM_AES are not.");
#endif

namespace osuCrypto {

    const AES mAesFixedKey(toBlock(45345336, -103343430));


    namespace details
    {
#if defined(OC_ENABLE_PORTABLE_AES) || defined(ENABLE_ARM_AES)
        auto SubWord(u32 x)
        {
            static constexpr u8 sbox[256] = {
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

            std::array<u8, 4> X;
            memcpy(&X, &x, sizeof(x));
            X[0] = sbox[X[0]];
            X[1] = sbox[X[1]];
            X[2] = sbox[X[2]];
            X[3] = sbox[X[3]];
            memcpy(&x, &X, sizeof(x));
            return x;
        }


        auto RotWord(u32 x) {
            std::array<u8, 4> X;
            memcpy(&X, &x, sizeof(x));
            const uint8_t u8tmp = X[0];
            X[0] = X[1];
            X[1] = X[2];
            X[2] = X[3];
            X[3] = u8tmp;
            memcpy(&x, &X, sizeof(x));
            return x;
        }
#endif

        template<u8 imm8, AESTypes type>
        block keyGenHelper(block key)
        {
            block keyRcon = [&]() {
#ifdef OC_ENABLE_AESNI
                if constexpr (type == AESTypes::NI)
                    return _mm_aeskeygenassist_si128(key, imm8);
#endif
#if defined(OC_ENABLE_PORTABLE_AES) || defined(ENABLE_ARM_AES)

                if constexpr (type == AESTypes::Portable || type == AESTypes::ARM)
                {
                    auto X3 = key.get<u32>(3);
                    //auto X2 = key.get<u32>(2);
                    auto X1 = key.get<u32>(1);
                    //auto X0 = key.get<u32>(0);
                    u32 RCON = imm8;
                    block keyRcon;
                    keyRcon.set<u32>(0, SubWord(X1));
                    keyRcon.set<u32>(1, RotWord(SubWord(X1)) ^ RCON);
                    keyRcon.set<u32>(2, SubWord(X3));
                    keyRcon.set<u32>(3, RotWord(SubWord(X3)) ^ RCON);
                    return keyRcon;
                }
#endif
                std::terminate();
                }();

            keyRcon = keyRcon.shuffle_epi32<0xFF>();
            key = key ^ key.slli_si128<4>();
            key = key ^ key.slli_si128<4>();
            key = key ^ key.slli_si128<4>();
            return key ^ keyRcon;
        };

        template<AESTypes type>
        void AES<type>::setKey(const block& userKey)
        {
            mRoundKey[0] = userKey;
            mRoundKey[1] = keyGenHelper<0x01, type>(mRoundKey[0]);
            mRoundKey[2] = keyGenHelper<0x02, type>(mRoundKey[1]);
            mRoundKey[3] = keyGenHelper<0x04, type>(mRoundKey[2]);
            mRoundKey[4] = keyGenHelper<0x08, type>(mRoundKey[3]);
            mRoundKey[5] = keyGenHelper<0x10, type>(mRoundKey[4]);
            mRoundKey[6] = keyGenHelper<0x20, type>(mRoundKey[5]);
            mRoundKey[7] = keyGenHelper<0x40, type>(mRoundKey[6]);
            mRoundKey[8] = keyGenHelper<0x80, type>(mRoundKey[7]);
            mRoundKey[9] = keyGenHelper<0x1B, type>(mRoundKey[8]);
            mRoundKey[10] = keyGenHelper<0x36, type>(mRoundKey[9]);
        }



#if defined(OC_ENABLE_PORTABLE_AES)
        constexpr u8 rsbox[256] = {
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


        //inline u8 getSBoxValue(int num) { return  sbox[num]; }
        inline u8 getSBoxInvert(int num) { return rsbox[num]; }

        std::array<std::array<u8, 4>, 4> unpackState(block& state)
        {
            auto r = std::array<std::array<u8, 4>, 4>{};
            static_assert(sizeof(r) == sizeof(state));
            memcpy(&r, &state, sizeof(r));
            return r;
        }

        block packState(std::array<std::array<u8, 4>, 4>& state)
        {
            auto r = block{};
            static_assert(sizeof(r) == sizeof(state));
            memcpy(&r, &state, sizeof(r));
            return r;
        }

        // The SubBytes Function Substitutes the values in the
        // state matrix with values in an S-box.
        inline void SubBytes(block& state)
        {
            state.set<u32>(0, SubWord(state.get<u32>(0)));
            state.set<u32>(1, SubWord(state.get<u32>(1)));
            state.set<u32>(2, SubWord(state.get<u32>(2)));
            state.set<u32>(3, SubWord(state.get<u32>(3)));
        }


        // The ShiftRows() function shifts the rows in the state to the left.
        // Each row is shifted with different offset.
        // Offset = Row number. So the first row is not shifted.
        inline void ShiftRows(block& state_)
        {
            uint8_t temp;
            auto state = unpackState(state_);

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

            state_ = packState(state);
        }

        constexpr uint8_t xtime(uint8_t x)
        {
            return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
        }

        constexpr uint8_t Multiply(uint8_t x, uint8_t y)
        {
            return (((y & 1) * x) ^
                ((y >> 1 & 1) * xtime(x)) ^
                ((y >> 2 & 1) * xtime(xtime(x))) ^
                ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
                ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
        }

        // MixColumns function mixes the columns of the state matrix
        inline void MixColumns(block& state_)
        {
            auto state = unpackState(state_);
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
            state_ = packState(state);
        }


        template<>
        block AES<Portable>::roundFn(block state, const block& roundKey)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            state = state ^ roundKey;
            return state;
        }

        template<>
        block AES<Portable>::penultimateFn(block state, const block& roundKey)
        {
            return roundFn(state, roundKey);
        }

        template<>
        block AES<Portable>::finalFn(block state, const block& roundKey)
        {
            SubBytes(state);
            ShiftRows(state);
            state = state ^ roundKey;
            return state;
        }
#endif

        // MixColumns function mixes the columns of the state matrix.
        // The method used to multiply may be difficult to understand for the inexperienced.
        // Please use the references to gain more information.
        template<AESTypes type>
        static void InvMixColumns(block& state_)
        {
#if defined(OC_ENABLE_PORTABLE_AES)
            if constexpr (type == AESTypes::Portable)
            {
                auto state = unpackState(state_);
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

                state_ = packState(state);
            }
            else
#endif
#ifdef OC_ENABLE_AESNI
                if constexpr (type == AESTypes::NI)
                {
                    state_ = _mm_aesimc_si128(state_);
                }
                else
#endif
#ifdef ENABLE_ARM_AES
                    if constexpr (type == AESTypes::ARM)
                    {
                        state_.mData = vaesimcq_u8(state_.mData);
                    }
                    else
#endif
                    {
                        std::terminate();
                        //static_assert(0, "unknown/unsupported AES type");
                    }
        }

#if defined(OC_ENABLE_PORTABLE_AES)
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
            auto state = unpackState(state_);

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

            state_ = packState(state);

        }


        template<>
        block AESDec<Portable>::firstFn(block state, const block& roundKey)
        {
            return state ^ roundKey;
        }

        template<>
        block AESDec<Portable>::roundFn(block state, const block& roundKey)
        {

            InvShiftRows(state);
            InvSubBytes(state);
            InvMixColumns<Portable>(state);
            state = state ^ roundKey;
            return state;
        }

        template<>
        block AESDec<Portable>::finalFn(block state, const block& roundKey)
        {
            InvShiftRows(state);
            InvSubBytes(state);
            state = state ^ roundKey;
            return state;
        }

#endif


        template<AESTypes type>
        void AESDec<type>::setKey(const block& userKey)
        {
            AES<type> aes;
            aes.setKey(userKey);

            // reverse the order
            mRoundKey[0] = aes.mRoundKey[10];

            // pre apply mixColumn inverse to the key. This matches what
            // the native instructions expect.
            for (u64 i = 1; i < 10; ++i)
            {
                mRoundKey[i] = aes.mRoundKey[10 - i];
                InvMixColumns<type>(mRoundKey[i]);
            }
            mRoundKey[10] = aes.mRoundKey[0];
        }

        template<AESTypes type>
        void AESDec<type>::ecbDecBlock(const block& ciphertext, block& plaintext)
        {
            plaintext = firstFn(ciphertext, mRoundKey[0]);
            plaintext = roundFn(plaintext, mRoundKey[1]);
            plaintext = roundFn(plaintext, mRoundKey[2]);
            plaintext = roundFn(plaintext, mRoundKey[3]);
            plaintext = roundFn(plaintext, mRoundKey[4]);
            plaintext = roundFn(plaintext, mRoundKey[5]);
            plaintext = roundFn(plaintext, mRoundKey[6]);
            plaintext = roundFn(plaintext, mRoundKey[7]);
            plaintext = roundFn(plaintext, mRoundKey[8]);
            plaintext = roundFn(plaintext, mRoundKey[9]);
            plaintext = finalFn(plaintext, mRoundKey[10]);
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

#ifdef ENABLE_ARM_AES
    template class details::AES<details::ARM>;
    template class details::AESDec<details::ARM>;
#endif

}
