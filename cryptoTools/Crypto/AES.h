#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>

namespace osuCrypto {

    namespace details
    {
        enum AESTypes
        {
            NI,
            Portable
        };

        template<AESTypes types>
        class AES
        {
        public:

            // Default constructor leave the class in an invalid state
            // until setKey(...) is called.
            AES() = default;
            AES(const AES&) = default;

            // Constructor to initialize the class with the given key
            AES(const block& userKey);

            // Set the key to be used for encryption.
            void setKey(const block& userKey);

            // Encrypts the plaintext block and stores the result in ciphertext
            void ecbEncBlock(const block& plaintext, block& ciphertext) const;

            // Encrypts the plaintext block and returns the result 
            block ecbEncBlock(const block& plaintext) const;

            // Encrypts blockLength starting at the plaintexts pointer and writes the result
            // to the ciphertext pointer
            void ecbEncBlocks(const block* plaintexts, u64 blockLength, block* ciphertext) const;

            void ecbEncBlocks(span<const block> plaintexts, span<block> ciphertext) const
            {
                if (plaintexts.size() != ciphertext.size())
                    throw RTE_LOC;
                ecbEncBlocks(plaintexts.data(), plaintexts.size(), ciphertext.data());
            }


            // Encrypts 2 blocks pointer to by plaintexts and writes the result to ciphertext
            void ecbEncTwoBlocks(const block* plaintexts, block* ciphertext) const;

            // Encrypts 4 blocks pointer to by plaintexts and writes the result to ciphertext
            void ecbEncFourBlocks(const block* plaintexts, block* ciphertext) const;

            // Encrypts 8 blocks pointer to by plaintexts and writes the result to ciphertext
            void ecbEnc8Blocks(const block* plaintexts, block* ciphertext) const
            {

                block temp[8];

                temp[0] = plaintexts[0] ^ mRoundKey[0];
                temp[1] = plaintexts[1] ^ mRoundKey[0];
                temp[2] = plaintexts[2] ^ mRoundKey[0];
                temp[3] = plaintexts[3] ^ mRoundKey[0];
                temp[4] = plaintexts[4] ^ mRoundKey[0];
                temp[5] = plaintexts[5] ^ mRoundKey[0];
                temp[6] = plaintexts[6] ^ mRoundKey[0];
                temp[7] = plaintexts[7] ^ mRoundKey[0];

                temp[0] = roundEnc(temp[0], mRoundKey[1]);
                temp[1] = roundEnc(temp[1], mRoundKey[1]);
                temp[2] = roundEnc(temp[2], mRoundKey[1]);
                temp[3] = roundEnc(temp[3], mRoundKey[1]);
                temp[4] = roundEnc(temp[4], mRoundKey[1]);
                temp[5] = roundEnc(temp[5], mRoundKey[1]);
                temp[6] = roundEnc(temp[6], mRoundKey[1]);
                temp[7] = roundEnc(temp[7], mRoundKey[1]);

                temp[0] = roundEnc(temp[0], mRoundKey[2]);
                temp[1] = roundEnc(temp[1], mRoundKey[2]);
                temp[2] = roundEnc(temp[2], mRoundKey[2]);
                temp[3] = roundEnc(temp[3], mRoundKey[2]);
                temp[4] = roundEnc(temp[4], mRoundKey[2]);
                temp[5] = roundEnc(temp[5], mRoundKey[2]);
                temp[6] = roundEnc(temp[6], mRoundKey[2]);
                temp[7] = roundEnc(temp[7], mRoundKey[2]);

                temp[0] = roundEnc(temp[0], mRoundKey[3]);
                temp[1] = roundEnc(temp[1], mRoundKey[3]);
                temp[2] = roundEnc(temp[2], mRoundKey[3]);
                temp[3] = roundEnc(temp[3], mRoundKey[3]);
                temp[4] = roundEnc(temp[4], mRoundKey[3]);
                temp[5] = roundEnc(temp[5], mRoundKey[3]);
                temp[6] = roundEnc(temp[6], mRoundKey[3]);
                temp[7] = roundEnc(temp[7], mRoundKey[3]);

                temp[0] = roundEnc(temp[0], mRoundKey[4]);
                temp[1] = roundEnc(temp[1], mRoundKey[4]);
                temp[2] = roundEnc(temp[2], mRoundKey[4]);
                temp[3] = roundEnc(temp[3], mRoundKey[4]);
                temp[4] = roundEnc(temp[4], mRoundKey[4]);
                temp[5] = roundEnc(temp[5], mRoundKey[4]);
                temp[6] = roundEnc(temp[6], mRoundKey[4]);
                temp[7] = roundEnc(temp[7], mRoundKey[4]);

                temp[0] = roundEnc(temp[0], mRoundKey[5]);
                temp[1] = roundEnc(temp[1], mRoundKey[5]);
                temp[2] = roundEnc(temp[2], mRoundKey[5]);
                temp[3] = roundEnc(temp[3], mRoundKey[5]);
                temp[4] = roundEnc(temp[4], mRoundKey[5]);
                temp[5] = roundEnc(temp[5], mRoundKey[5]);
                temp[6] = roundEnc(temp[6], mRoundKey[5]);
                temp[7] = roundEnc(temp[7], mRoundKey[5]);

                temp[0] = roundEnc(temp[0], mRoundKey[6]);
                temp[1] = roundEnc(temp[1], mRoundKey[6]);
                temp[2] = roundEnc(temp[2], mRoundKey[6]);
                temp[3] = roundEnc(temp[3], mRoundKey[6]);
                temp[4] = roundEnc(temp[4], mRoundKey[6]);
                temp[5] = roundEnc(temp[5], mRoundKey[6]);
                temp[6] = roundEnc(temp[6], mRoundKey[6]);
                temp[7] = roundEnc(temp[7], mRoundKey[6]);

                temp[0] = roundEnc(temp[0], mRoundKey[7]);
                temp[1] = roundEnc(temp[1], mRoundKey[7]);
                temp[2] = roundEnc(temp[2], mRoundKey[7]);
                temp[3] = roundEnc(temp[3], mRoundKey[7]);
                temp[4] = roundEnc(temp[4], mRoundKey[7]);
                temp[5] = roundEnc(temp[5], mRoundKey[7]);
                temp[6] = roundEnc(temp[6], mRoundKey[7]);
                temp[7] = roundEnc(temp[7], mRoundKey[7]);

                temp[0] = roundEnc(temp[0], mRoundKey[8]);
                temp[1] = roundEnc(temp[1], mRoundKey[8]);
                temp[2] = roundEnc(temp[2], mRoundKey[8]);
                temp[3] = roundEnc(temp[3], mRoundKey[8]);
                temp[4] = roundEnc(temp[4], mRoundKey[8]);
                temp[5] = roundEnc(temp[5], mRoundKey[8]);
                temp[6] = roundEnc(temp[6], mRoundKey[8]);
                temp[7] = roundEnc(temp[7], mRoundKey[8]);

                temp[0] = roundEnc(temp[0], mRoundKey[9]);
                temp[1] = roundEnc(temp[1], mRoundKey[9]);
                temp[2] = roundEnc(temp[2], mRoundKey[9]);
                temp[3] = roundEnc(temp[3], mRoundKey[9]);
                temp[4] = roundEnc(temp[4], mRoundKey[9]);
                temp[5] = roundEnc(temp[5], mRoundKey[9]);
                temp[6] = roundEnc(temp[6], mRoundKey[9]);
                temp[7] = roundEnc(temp[7], mRoundKey[9]);

                ciphertext[0] = finalEnc(temp[0], mRoundKey[10]);
                ciphertext[1] = finalEnc(temp[1], mRoundKey[10]);
                ciphertext[2] = finalEnc(temp[2], mRoundKey[10]);
                ciphertext[3] = finalEnc(temp[3], mRoundKey[10]);
                ciphertext[4] = finalEnc(temp[4], mRoundKey[10]);
                ciphertext[5] = finalEnc(temp[5], mRoundKey[10]);
                ciphertext[6] = finalEnc(temp[6], mRoundKey[10]);
                ciphertext[7] = finalEnc(temp[7], mRoundKey[10]);
            }

            // Encrypts 16 blocks pointer to by plaintexts and writes the result to ciphertext
            void ecbEnc16Blocks(const block* plaintexts, block* ciphertext) const;

            // Encrypts the vector of blocks {baseIdx, baseIdx + 1, ..., baseIdx + length - 1} 
            // and writes the result to ciphertext.
            void ecbEncCounterMode(u64 baseIdx, u64 length, block* ciphertext) const
            {
                ecbEncCounterMode(toBlock(baseIdx), length, ciphertext);
            }
            void ecbEncCounterMode(u64 baseIdx, span<block> ciphertext) const
            {
                ecbEncCounterMode(toBlock(baseIdx), ciphertext.size(), ciphertext.data());
            }
            void ecbEncCounterMode(block baseIdx, span<block> ciphertext) const
            {
                ecbEncCounterMode(baseIdx, ciphertext.size(), ciphertext.data());
            }
            void ecbEncCounterMode(block baseIdx, u64 length, block* ciphertext) const;



            // Returns the current key.
            const block& getKey() const { return mRoundKey[0]; }

            static block roundEnc(block state, const block& roundKey);
            static block finalEnc(block state, const block& roundKey);

            // The expanded key.
            std::array<block,11> mRoundKey;
        };

#ifdef OC_ENABLE_AESNI
        template<>
        inline block AES<NI>::finalEnc(block state, const block& roundKey)
        {
            return _mm_aesenclast_si128(state, roundKey);
        }

        template<>
        inline block AES<NI>::roundEnc(block state, const block& roundKey)
        {
            return _mm_aesenc_si128(state, roundKey);
        }
#endif

        // A class to perform AES decryption.
        template<AESTypes type>
        class AESDec
        {
        public:
            AESDec() = default;
            AESDec(const AESDec&) = default;
            AESDec(const block& userKey);

            void setKey(const block& userKey);
            void ecbDecBlock(const block& ciphertext, block& plaintext);
            block ecbDecBlock(const block& ciphertext);

            std::array<block,11> mRoundKey;


            static block roundDec(block state, const block& roundKey);
            static block finalDec(block state, const block& roundKey);

        };
        //void InvCipher(block& state, std::array<block, 11>& RoundKey);


    }

#ifdef OC_ENABLE_AESNI
    using AES = details::AES<details::NI>;
    using AESDec = details::AESDec<details::NI>;
#else
    using AES = details::AES<details::Portable>;
    using AESDec = details::AESDec<details::Portable>;
#endif


    // Specialization of the AES class to support encryption of N values under N different keys
    template<int N>
    class MultiKeyAES
    {
    public:
        std::array<AES, N> mAESs;

        // Default constructor leave the class in an invalid state
        // until setKey(...) is called.
        MultiKeyAES() = default;

        // Constructor to initialize the class with the given key
        MultiKeyAES(span<block> keys) { setKeys(keys); }

        // Set the N keys to be used for encryption.
        void setKeys(span<block> keys)
        {
            for (u64 i = 0; i < N; ++i)
            {
                mAESs[i].setKey(keys[i]);
            }
        }

        // Computes the encrpytion of N blocks pointed to by plaintext 
        // and stores the result at ciphertext.
        void ecbEncNBlocks(const block* plaintext, block* ciphertext) const
        {
            for (int i = 0; i < N; ++i) ciphertext[i] = plaintext[i] ^ mAESs[i].mRoundKey[0];
            for (int i = 0; i < N; ++i) ciphertext[i] = AES::roundEnc(ciphertext[i], mAESs[i].mRoundKey[1]);
            for (int i = 0; i < N; ++i) ciphertext[i] = AES::roundEnc(ciphertext[i], mAESs[i].mRoundKey[2]);
            for (int i = 0; i < N; ++i) ciphertext[i] = AES::roundEnc(ciphertext[i], mAESs[i].mRoundKey[3]);
            for (int i = 0; i < N; ++i) ciphertext[i] = AES::roundEnc(ciphertext[i], mAESs[i].mRoundKey[4]);
            for (int i = 0; i < N; ++i) ciphertext[i] = AES::roundEnc(ciphertext[i], mAESs[i].mRoundKey[5]);
            for (int i = 0; i < N; ++i) ciphertext[i] = AES::roundEnc(ciphertext[i], mAESs[i].mRoundKey[6]);
            for (int i = 0; i < N; ++i) ciphertext[i] = AES::roundEnc(ciphertext[i], mAESs[i].mRoundKey[7]);
            for (int i = 0; i < N; ++i) ciphertext[i] = AES::roundEnc(ciphertext[i], mAESs[i].mRoundKey[8]);
            for (int i = 0; i < N; ++i) ciphertext[i] = AES::roundEnc(ciphertext[i], mAESs[i].mRoundKey[9]);
            for (int i = 0; i < N; ++i) ciphertext[i] = AES::finalEnc(ciphertext[i], mAESs[i].mRoundKey[10]);
        }

        // Utility to compare the keys.
        const MultiKeyAES<N>& operator=(const MultiKeyAES<N>& rhs)
        {
            for (u64 i = 0; i < N; ++i)
                for (u64 j = 0; j < 11; ++j)
                    mAESs[i].mRoundKey[j] = rhs.mAESs[i].mRoundKey[j];

            return rhs;
        }
    };


    //// A class to perform AES decryption.
    //class AESDec2
    //{
    //public:
    //    AESDec2() = default;
    //    AESDec2(const AESDec2&) = default;
    //    AESDec2(const block& userKey);
    //
    //    void setKey(const block& userKey);
    //    void ecbDecBlock(const block& ciphertext, block& plaintext);
    //    block ecbDecBlock(const block& ciphertext);
    //
    //    block mRoundKey[11];
    //
    //};


    // An AES instance with a fixed and public key.
    extern const AES mAesFixedKey;


}
