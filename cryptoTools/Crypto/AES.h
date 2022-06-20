#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>
#include <type_traits>

namespace osuCrypto {

    namespace details
    {
        enum AESTypes
        {
            NI,
            Portable
        };

        template<AESTypes type>
        class AES
        {
        public:
            static const u64 rounds = 10;

            // Default constructor leave the class in an invalid state
            // until setKey(...) is called.
            AES() = default;
            AES(const AES&) = default;

            // Constructor to initialize the class with the given key
            AES(const block& userKey);

            // Set the key to be used for encryption.
            void setKey(const block& userKey);

            // Use this function (or other *Inline functions) if you want to force inlining.
            template<u64 blocks>
            OC_FORCEINELINE typename std::enable_if<(blocks <= 16)>::type
            ecbEncBlocksInline(const block* plaintext, block* ciphertext) const
            {
                for (u64 j = 0; j < blocks; ++j)
                    ciphertext[j] = plaintext[j] ^ mRoundKey[0];
                for (u64 i = 1; i < rounds; ++i)
                    roundEncBlocks<blocks>(ciphertext, ciphertext, mRoundKey[i]);
                finalEncBlocks<blocks>(ciphertext, ciphertext, mRoundKey[rounds]);
            }

            template<u64 blocks>
            OC_FORCEINELINE void
            ecbEncBlocksInline(const block (&plaintext)[blocks], block (&ciphertext)[blocks]) const
            {
                ecbEncBlocksInline<blocks>(&plaintext[0], &ciphertext[0]);
            }

            // Fall back to encryption loop rather than doing way too many blocks at once.
            template<u64 blocks>
            OC_FORCEINELINE typename std::enable_if<(blocks > 16)>::type
            ecbEncBlocksInline(const block* plaintext, block* ciphertext) const
            {
                ecbEncBlocks(plaintext, blocks, ciphertext);
            }

            // Not necessarily inlined version. See specialization below class for more information.
            template<u64 blocks>
            inline void ecbEncBlocks(const block* plaintext, block* ciphertext) const
            {
                ecbEncBlocksInline<blocks>(plaintext, ciphertext);
            }

            //template<u64 blocks>
            //inline void ecbEncBlocks(const block (&plaintext)[blocks], block (&ciphertext)[blocks]) const
            //{
            //    ecbEncBlocks<blocks>(&plaintext[0], &ciphertext[0]);
            //}

            // Encrypts the plaintext block and stores the result in ciphertext
            inline void ecbEncBlock(const block& plaintext, block& ciphertext) const
            {
                ecbEncBlocks<1>(&plaintext, &ciphertext);
            }

            // Encrypts the plaintext block and returns the result
            inline block ecbEncBlock(const block& plaintext) const
            {
                block ciphertext;
                ecbEncBlock(plaintext, ciphertext);
                return ciphertext;
            }

            // Encrypts 2 blocks pointed to by plaintext and writes the result to ciphertext
            inline void ecbEncTwoBlocks(const block* plaintext, block* ciphertext) const
            {
                return ecbEncBlocks<2>(plaintext, ciphertext);
            }

            // Encrypts 4 blocks pointed to by plaintext and writes the result to ciphertext
            inline void ecbEncFourBlocks(const block* plaintext, block* ciphertext) const
            {
                return ecbEncBlocks<4>(plaintext, ciphertext);
            }

            // Encrypts 8 blocks pointed to by plaintext and writes the result to ciphertext
            inline void ecbEnc8Blocks(const block* plaintext, block* ciphertext) const
            {
                ecbEncBlocks<8>(plaintext, ciphertext);
            }

            // Encrypts 16 blocks pointed to by plaintext and writes the result to ciphertext
            void ecbEnc16Blocks(const block* plaintext, block* ciphertext) const
            {
                ecbEncBlocks<16>(plaintext, ciphertext);
            }

            // Encrypts blockLength starting at the plaintext pointer and writes the result
            // to the ciphertext pointer
            inline void ecbEncBlocks(const block* plaintext, u64 blockLength, block* ciphertext) const
            {
                const u64 step = 8;
                u64 idx = 0;

                for (; idx + step <= blockLength; idx += step)
                {
                    ecbEncBlocks<step>(plaintext + idx, ciphertext + idx);
                }

                i32 misalignment = blockLength % step;
                switch (misalignment) {
                    #define SWITCH_CASE(n) \
                    case n: \
                        ecbEncBlocks<n>(plaintext + idx, ciphertext + idx); \
                        break;
                    SWITCH_CASE(1)
                    SWITCH_CASE(2)
                    SWITCH_CASE(3)
                    SWITCH_CASE(4)
                    SWITCH_CASE(5)
                    SWITCH_CASE(6)
                    SWITCH_CASE(7)
                    #undef SWITCH_CASE
                }
            }

            inline void ecbEncBlocks(span<const block> plaintext, span<block> ciphertext) const
            {
                if (plaintext.size() != ciphertext.size())
                    throw RTE_LOC;
                ecbEncBlocks(plaintext.data(), plaintext.size(), ciphertext.data());
            }


            // Correlation robust hash function.
            template<u64 blocks>
            OC_FORCEINELINE typename std::enable_if<(blocks <= 16)>::type
            hashBlocks(const block* plaintext, block* ciphertext) const
            {
                block buff[blocks];
                ecbEncBlocks<blocks>(plaintext, buff);
                hashBlocksFinalXor<blocks>(plaintext, buff, ciphertext);
            }

            // Fall back to encryption loop rather than unrolling way too many blocks.
            template<u64 blocks>
            OC_FORCEINELINE typename std::enable_if<(blocks > 16)>::type
            hashBlocks(const block* plaintext, block* ciphertext) const
            {
                hashBlocks(plaintext, blocks, ciphertext);
            }

        private:
            // Use template for loop unrolling.
            template<u64 blocks>
            static OC_FORCEINELINE typename std::enable_if<(blocks > 0)>::type
            hashBlocksFinalXor(const block* plaintext, block* buff, block* ciphertext)
            {
                buff[blocks - 1] ^= plaintext[blocks - 1];
                hashBlocksFinalXor<blocks - 1>(plaintext, buff, ciphertext);

                // Only write to ciphertext after computing the entire output, so the compiler won't
                // have to worry about ciphertext aliasing plaintext.
                ciphertext[blocks - 1] = buff[blocks - 1];
            }
            template<u64 blocks>
            static OC_FORCEINELINE typename std::enable_if<(blocks == 0)>::type
            hashBlocksFinalXor(const block* plaintext, const block* buff, block* ciphertext) {}

        public:
            template<u64 blocks>
            inline void hashBlocks(const block (&plaintext)[blocks], block (&ciphertext)[blocks]) const
            {
                hashBlocks<blocks>(&plaintext[0], &ciphertext[0]);
            }

            inline block hashBlock(const block& plaintext) const
            {
                block ciphertext;
                hashBlocks<1>(&plaintext, &ciphertext);
                return ciphertext;
            }

            inline void hash8Blocks(const block* plaintext, block* ciphertext) const
            {
                hashBlocks<8>(plaintext, ciphertext);
            }

            inline void hashBlocks(const block* plaintext, u64 blockLength, block* ciphertext) const
            {
                const u64 step = 8;
                u64 idx = 0;

                for (; idx + step <= blockLength; idx += step)
                {
                    hashBlocks<step>(plaintext + idx, ciphertext + idx);
                }

                i32 misalignment = blockLength % step;
                switch (misalignment) {
                    #define SWITCH_CASE(n) \
                    case n: \
                        hashBlocks<n>(plaintext + idx, ciphertext + idx); \
                        break;
                    SWITCH_CASE(1)
                    SWITCH_CASE(2)
                    SWITCH_CASE(3)
                    SWITCH_CASE(4)
                    SWITCH_CASE(5)
                    SWITCH_CASE(6)
                    SWITCH_CASE(7)
                    #undef SWITCH_CASE
                }
            }

            inline void hashBlocks(span<const block> plaintext, span<block> ciphertext) const
            {
                if (plaintext.size() != ciphertext.size())
                    throw RTE_LOC;
                hashBlocks(plaintext.data(), plaintext.size(), ciphertext.data());
            }


            // Encrypts the vector of blocks {baseIdx, baseIdx + 1, ..., baseIdx + blockLength - 1}
            // and writes the result to ciphertext.
            void ecbEncCounterMode(u64 baseIdx, u64 blockLength, block* ciphertext) const
            {
                ecbEncCounterMode(toBlock(baseIdx), blockLength, ciphertext);
            }
            void ecbEncCounterMode(u64 baseIdx, span<block> ciphertext) const
            {
                ecbEncCounterMode(toBlock(baseIdx), ciphertext.size(), ciphertext.data());
            }
            void ecbEncCounterMode(block baseIdx, span<block> ciphertext) const
            {
                ecbEncCounterMode(baseIdx, ciphertext.size(), ciphertext.data());
            }
            void ecbEncCounterMode(block baseIdx, u64 blockLength, block* ciphertext) const
            {
                ecbEncCounterModeImpl(baseIdx, blockLength, ciphertext[0].data());
            }

            // Use this version (which writes to a u8* pointer) for unaligned output.
            void ecbEncCounterMode(block baseIdx, u64 byteLength, u8* ciphertext) const
            {
                if (byteLength % sizeof(block))
                    throw RTE_LOC;
                ecbEncCounterModeImpl(baseIdx, byteLength / sizeof(block), ciphertext);
            }
            void ecbEncCounterMode(u64 baseIdx, u64 blockLength, u8* ciphertext) const
            {
                ecbEncCounterMode(toBlock(baseIdx), blockLength, ciphertext);
            }

        private:
            // For simplicity, all CTR modes are defined in terms of the unaligned version.
            void ecbEncCounterModeImpl(block baseIdx, u64 blockLength, u8* ciphertext) const;

        public:
            // Returns the current key.
            const block& getKey() const { return mRoundKey[0]; }

            static block roundEnc(block state, const block& roundKey);
            static block finalEnc(block state, const block& roundKey);

            template<u64 blocks>
            static OC_FORCEINELINE typename std::enable_if<(blocks > 0)>::type
            roundEncBlocks(const block* stateIn, block* stateOut, const block& roundKey)
            {
                // Force unrolling using template recursion.
                roundEncBlocks<blocks - 1>(stateIn, stateOut, roundKey);
                stateOut[blocks - 1] = roundEnc(stateIn[blocks - 1], roundKey);
            }

            template<u64 blocks>
            static OC_FORCEINELINE typename std::enable_if<(blocks > 0)>::type
            finalEncBlocks(const block* stateIn, block* stateOut, const block& roundKey)
            {
                finalEncBlocks<blocks - 1>(stateIn, stateOut, roundKey);
                stateOut[blocks - 1] = finalEnc(stateIn[blocks - 1], roundKey);
            }

            // Base case
            template<u64 blocks>
            static OC_FORCEINELINE typename std::enable_if<blocks == 0>::type
            roundEncBlocks(const block* stateIn, block* stateOut, const block& roundKey) {}

            template<u64 blocks>
            static OC_FORCEINELINE typename std::enable_if<blocks == 0>::type
            finalEncBlocks(const block* stateIn, block* stateOut, const block& roundKey) {}

            // The expanded key.
            std::array<block,rounds + 1> mRoundKey;
        };

#ifdef OC_ENABLE_AESNI
        template<>
        void AES<NI>::setKey(const block& userKey);

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

#if (defined(__GNUC__) || defined(__clang__)) && defined(__OPTIMIZE__) && defined(OC_UNSTABLE_OPTIMIZATIONS)
        // Use asm hacks to define a custom calling convention, so that the plaintext and ciphertext
        // get passed in registers. This is possible without asm hacking for the inputs, but there's
        // no way to get GCC's calling convention to put more than one output in a SSE register.
        //
        // The blocks go in registers xmm0..., and the outputs are returned in place. However, the
        // first key XOR takes place in ecbEncBlocks instead of in ecbEncBlocksCustomCallingConv.
        // A pointer to the AES<NI> class is passed in rdi. The only clobbered registers are r10,
        // xmm14, and xmm15. (With the exception of maybe the legacy mmx and x87 registers, as I
        // don't know what to do with them, but they don't matter.) The inline assembly only works
        // up to 14 blocks, due to a GCC limitation:
        // https://gcc.gnu.org/legacy-ml/gcc-help/2008-03/msg00109.html
        //
        // Compiling without optimization causes problems for this because the compiler will emit
        // some boilerplate code that gets in the way, so the #if above also checks to make sure
        // that optimization is turned on.
        //
        // 128 is subtracted from & added to rsp to avoid clobbering the red zone. See
        // https://stackoverflow.com/a/47402504/4071916

        #define AES_SPECIALIZE_ENC_BLOCKS(n) \
        __attribute__((sysv_abi)) void ecbEncBlocksCustomCallingConv##n(); \
        \
        template<> template<> OC_FORCEINELINE \
        void AES<NI>::ecbEncBlocks<n>(const block* plaintext, block* ciphertext) const \
        { \
            register __m128i AES_ENC_BLOCKS_VARS_##n; \
            __asm__ ( \
                  "addq $-128, %%rsp\n\t" \
                  AES_ENC_BLOCKS_CALL_INSN \
                  "subq $-128, %%rsp\n\t" \
                : AES_ENC_BLOCKS_OUTS_##n \
                : [func] AES_ENC_BLOCKS_CALL_CONSTRAINT (ecbEncBlocksCustomCallingConv##n), "D" (this) \
                : "cc", "r10", "xmm14", "xmm15" \
                , "mm0","mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm6" \
                , "st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)"); \
            AES_ENC_BLOCKS_ASSIGN_CT_##n \
        }

#ifndef __clang__
        // ".intel_syntax noprefix" is a workaround for the warning:
        // "Assembler messages: Warning: indirect call without `*'"
        // If the * were added then when its a direct call it would produce different machine code.
        // AT&T call instructions need different syntax for labels vs registers, while for Intel
        // they are the same, which fixes the problem.
        #define AES_ENC_BLOCKS_CALL_INSN \
            ".intel_syntax noprefix\n\t" \
            "call %P[func]\n\t" \
            ".att_syntax\n\t"
        #define AES_ENC_BLOCKS_CALL_CONSTRAINT "ir"
#else
        // Calling a label seems to just fail on clang, so always use indirect calls.
        #define AES_ENC_BLOCKS_CALL_INSN \
            "call *%[func]\n\t"
        #define AES_ENC_BLOCKS_CALL_CONSTRAINT "r"
#endif

        #define AES_ENC_BLOCKS_ASSIGN_CT_1                              ciphertext[0]  = __m128i(ct0 );
        #define AES_ENC_BLOCKS_ASSIGN_CT_2  AES_ENC_BLOCKS_ASSIGN_CT_1  ciphertext[1]  = __m128i(ct1 );
        #define AES_ENC_BLOCKS_ASSIGN_CT_3  AES_ENC_BLOCKS_ASSIGN_CT_2  ciphertext[2]  = __m128i(ct2 );
        #define AES_ENC_BLOCKS_ASSIGN_CT_4  AES_ENC_BLOCKS_ASSIGN_CT_3  ciphertext[3]  = __m128i(ct3 );
        #define AES_ENC_BLOCKS_ASSIGN_CT_5  AES_ENC_BLOCKS_ASSIGN_CT_4  ciphertext[4]  = __m128i(ct4 );
        #define AES_ENC_BLOCKS_ASSIGN_CT_6  AES_ENC_BLOCKS_ASSIGN_CT_5  ciphertext[5]  = __m128i(ct5 );
        #define AES_ENC_BLOCKS_ASSIGN_CT_7  AES_ENC_BLOCKS_ASSIGN_CT_6  ciphertext[6]  = __m128i(ct6 );
        #define AES_ENC_BLOCKS_ASSIGN_CT_8  AES_ENC_BLOCKS_ASSIGN_CT_7  ciphertext[7]  = __m128i(ct7 );
        #define AES_ENC_BLOCKS_ASSIGN_CT_9  AES_ENC_BLOCKS_ASSIGN_CT_8  ciphertext[8]  = __m128i(ct8 );
        #define AES_ENC_BLOCKS_ASSIGN_CT_10 AES_ENC_BLOCKS_ASSIGN_CT_9  ciphertext[9]  = __m128i(ct9 );
        #define AES_ENC_BLOCKS_ASSIGN_CT_11 AES_ENC_BLOCKS_ASSIGN_CT_10 ciphertext[10] = __m128i(ct10);
        #define AES_ENC_BLOCKS_ASSIGN_CT_12 AES_ENC_BLOCKS_ASSIGN_CT_11 ciphertext[11] = __m128i(ct11);
        #define AES_ENC_BLOCKS_ASSIGN_CT_13 AES_ENC_BLOCKS_ASSIGN_CT_12 ciphertext[12] = __m128i(ct12);
        #define AES_ENC_BLOCKS_ASSIGN_CT_14 AES_ENC_BLOCKS_ASSIGN_CT_13 ciphertext[13] = __m128i(ct13);

        #define AES_ENC_BLOCKS_VARS_1                          ct0  __asm__("xmm0")  = plaintext[0]  ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_2  AES_ENC_BLOCKS_VARS_1,  ct1  __asm__("xmm1")  = plaintext[1]  ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_3  AES_ENC_BLOCKS_VARS_2,  ct2  __asm__("xmm2")  = plaintext[2]  ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_4  AES_ENC_BLOCKS_VARS_3,  ct3  __asm__("xmm3")  = plaintext[3]  ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_5  AES_ENC_BLOCKS_VARS_4,  ct4  __asm__("xmm4")  = plaintext[4]  ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_6  AES_ENC_BLOCKS_VARS_5,  ct5  __asm__("xmm5")  = plaintext[5]  ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_7  AES_ENC_BLOCKS_VARS_6,  ct6  __asm__("xmm6")  = plaintext[6]  ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_8  AES_ENC_BLOCKS_VARS_7,  ct7  __asm__("xmm7")  = plaintext[7]  ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_9  AES_ENC_BLOCKS_VARS_8,  ct8  __asm__("xmm8")  = plaintext[8]  ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_10 AES_ENC_BLOCKS_VARS_9,  ct9  __asm__("xmm9")  = plaintext[9]  ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_11 AES_ENC_BLOCKS_VARS_10, ct10 __asm__("xmm10") = plaintext[10] ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_12 AES_ENC_BLOCKS_VARS_11, ct11 __asm__("xmm11") = plaintext[11] ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_13 AES_ENC_BLOCKS_VARS_12, ct12 __asm__("xmm12") = plaintext[12] ^ mRoundKey[0]
        #define AES_ENC_BLOCKS_VARS_14 AES_ENC_BLOCKS_VARS_13, ct13 __asm__("xmm13") = plaintext[13] ^ mRoundKey[0]

        #define AES_ENC_BLOCKS_OUTS_1                          "+x" (ct0)
        #define AES_ENC_BLOCKS_OUTS_2  AES_ENC_BLOCKS_OUTS_1,  "+x" (ct1)
        #define AES_ENC_BLOCKS_OUTS_3  AES_ENC_BLOCKS_OUTS_2,  "+x" (ct2)
        #define AES_ENC_BLOCKS_OUTS_4  AES_ENC_BLOCKS_OUTS_3,  "+x" (ct3)
        #define AES_ENC_BLOCKS_OUTS_5  AES_ENC_BLOCKS_OUTS_4,  "+x" (ct4)
        #define AES_ENC_BLOCKS_OUTS_6  AES_ENC_BLOCKS_OUTS_5,  "+x" (ct5)
        #define AES_ENC_BLOCKS_OUTS_7  AES_ENC_BLOCKS_OUTS_6,  "+x" (ct6)
        #define AES_ENC_BLOCKS_OUTS_8  AES_ENC_BLOCKS_OUTS_7,  "+x" (ct7)
        #define AES_ENC_BLOCKS_OUTS_9  AES_ENC_BLOCKS_OUTS_8,  "+x" (ct8)
        #define AES_ENC_BLOCKS_OUTS_10 AES_ENC_BLOCKS_OUTS_9,  "+x" (ct9)
        #define AES_ENC_BLOCKS_OUTS_11 AES_ENC_BLOCKS_OUTS_10, "+x" (ct10)
        #define AES_ENC_BLOCKS_OUTS_12 AES_ENC_BLOCKS_OUTS_11, "+x" (ct11)
        #define AES_ENC_BLOCKS_OUTS_13 AES_ENC_BLOCKS_OUTS_12, "+x" (ct12)
        #define AES_ENC_BLOCKS_OUTS_14 AES_ENC_BLOCKS_OUTS_13, "+x" (ct13)

        AES_SPECIALIZE_ENC_BLOCKS(1)
        AES_SPECIALIZE_ENC_BLOCKS(2)
        AES_SPECIALIZE_ENC_BLOCKS(3)
        AES_SPECIALIZE_ENC_BLOCKS(4)
        AES_SPECIALIZE_ENC_BLOCKS(5)
        AES_SPECIALIZE_ENC_BLOCKS(6)
        AES_SPECIALIZE_ENC_BLOCKS(7)
        AES_SPECIALIZE_ENC_BLOCKS(8)
        AES_SPECIALIZE_ENC_BLOCKS(9)
        AES_SPECIALIZE_ENC_BLOCKS(10)
        AES_SPECIALIZE_ENC_BLOCKS(11)
        AES_SPECIALIZE_ENC_BLOCKS(12)
        AES_SPECIALIZE_ENC_BLOCKS(13)
        AES_SPECIALIZE_ENC_BLOCKS(14)

        // Done. Undefine everything again.
        #undef AES_SPECIALIZE_ENC_BLOCKS

        #undef AES_ENC_BLOCKS_ASSIGN_CT_1
        #undef AES_ENC_BLOCKS_ASSIGN_CT_2
        #undef AES_ENC_BLOCKS_ASSIGN_CT_3
        #undef AES_ENC_BLOCKS_ASSIGN_CT_4
        #undef AES_ENC_BLOCKS_ASSIGN_CT_5
        #undef AES_ENC_BLOCKS_ASSIGN_CT_6
        #undef AES_ENC_BLOCKS_ASSIGN_CT_7
        #undef AES_ENC_BLOCKS_ASSIGN_CT_8
        #undef AES_ENC_BLOCKS_ASSIGN_CT_9
        #undef AES_ENC_BLOCKS_ASSIGN_CT_10
        #undef AES_ENC_BLOCKS_ASSIGN_CT_11
        #undef AES_ENC_BLOCKS_ASSIGN_CT_12
        #undef AES_ENC_BLOCKS_ASSIGN_CT_13
        #undef AES_ENC_BLOCKS_ASSIGN_CT_14

        #undef AES_ENC_BLOCKS_VARS_1
        #undef AES_ENC_BLOCKS_VARS_2
        #undef AES_ENC_BLOCKS_VARS_3
        #undef AES_ENC_BLOCKS_VARS_4
        #undef AES_ENC_BLOCKS_VARS_5
        #undef AES_ENC_BLOCKS_VARS_6
        #undef AES_ENC_BLOCKS_VARS_7
        #undef AES_ENC_BLOCKS_VARS_8
        #undef AES_ENC_BLOCKS_VARS_9
        #undef AES_ENC_BLOCKS_VARS_10
        #undef AES_ENC_BLOCKS_VARS_11
        #undef AES_ENC_BLOCKS_VARS_12
        #undef AES_ENC_BLOCKS_VARS_13
        #undef AES_ENC_BLOCKS_VARS_14

        #undef AES_ENC_BLOCKS_OUTS_1
        #undef AES_ENC_BLOCKS_OUTS_2
        #undef AES_ENC_BLOCKS_OUTS_3
        #undef AES_ENC_BLOCKS_OUTS_4
        #undef AES_ENC_BLOCKS_OUTS_5
        #undef AES_ENC_BLOCKS_OUTS_6
        #undef AES_ENC_BLOCKS_OUTS_7
        #undef AES_ENC_BLOCKS_OUTS_8
        #undef AES_ENC_BLOCKS_OUTS_9
        #undef AES_ENC_BLOCKS_OUTS_10
        #undef AES_ENC_BLOCKS_OUTS_11
        #undef AES_ENC_BLOCKS_OUTS_12
        #undef AES_ENC_BLOCKS_OUTS_13
        #undef AES_ENC_BLOCKS_OUTS_14

        #undef AES_ENC_BLOCKS_INS_1
        #undef AES_ENC_BLOCKS_INS_2
        #undef AES_ENC_BLOCKS_INS_3
        #undef AES_ENC_BLOCKS_INS_4
        #undef AES_ENC_BLOCKS_INS_5
        #undef AES_ENC_BLOCKS_INS_6
        #undef AES_ENC_BLOCKS_INS_7
        #undef AES_ENC_BLOCKS_INS_8
        #undef AES_ENC_BLOCKS_INS_9
        #undef AES_ENC_BLOCKS_INS_10
        #undef AES_ENC_BLOCKS_INS_11
        #undef AES_ENC_BLOCKS_INS_12
        #undef AES_ENC_BLOCKS_INS_13
        #undef AES_ENC_BLOCKS_INS_14
#endif
#endif

        // A class to perform AES decryption.
        template<AESTypes type>
        class AESDec
        {
        public:
            static const u64 rounds = AES<type>::rounds;

            AESDec() = default;
            AESDec(const AESDec&) = default;

            AESDec(const block& key)
            {
                setKey(key);
            }

            void setKey(const block& userKey);
            void ecbDecBlock(const block& ciphertext, block& plaintext);

            block ecbDecBlock(const block& ciphertext)
            {
                block ret;
                ecbDecBlock(ciphertext, ret);
                return ret;
            }

            std::array<block,rounds + 1> mRoundKey;


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

#ifdef OC_ENABLE_AESNI

        // TODO: use technique from "Fast Garbling of Circuits Under Standard Assumptions".
        template<int SS>
        void keyGenHelper8(std::array<block,8>& key)
        {
            std::array<block, 8> keyRcon, t, p;
            keyRcon[0] = _mm_aeskeygenassist_si128(key[0], SS);
            keyRcon[1] = _mm_aeskeygenassist_si128(key[1], SS);
            keyRcon[2] = _mm_aeskeygenassist_si128(key[2], SS);
            keyRcon[3] = _mm_aeskeygenassist_si128(key[3], SS);
            keyRcon[4] = _mm_aeskeygenassist_si128(key[4], SS);
            keyRcon[5] = _mm_aeskeygenassist_si128(key[5], SS);
            keyRcon[6] = _mm_aeskeygenassist_si128(key[6], SS);
            keyRcon[7] = _mm_aeskeygenassist_si128(key[7], SS);

            keyRcon[0] = _mm_shuffle_epi32(keyRcon[0], _MM_SHUFFLE(3, 3, 3, 3));
            keyRcon[1] = _mm_shuffle_epi32(keyRcon[1], _MM_SHUFFLE(3, 3, 3, 3));
            keyRcon[2] = _mm_shuffle_epi32(keyRcon[2], _MM_SHUFFLE(3, 3, 3, 3));
            keyRcon[3] = _mm_shuffle_epi32(keyRcon[3], _MM_SHUFFLE(3, 3, 3, 3));
            keyRcon[4] = _mm_shuffle_epi32(keyRcon[4], _MM_SHUFFLE(3, 3, 3, 3));
            keyRcon[5] = _mm_shuffle_epi32(keyRcon[5], _MM_SHUFFLE(3, 3, 3, 3));
            keyRcon[6] = _mm_shuffle_epi32(keyRcon[6], _MM_SHUFFLE(3, 3, 3, 3));
            keyRcon[7] = _mm_shuffle_epi32(keyRcon[7], _MM_SHUFFLE(3, 3, 3, 3));

            p[0] = key[0];
            p[1] = key[1];
            p[2] = key[2];
            p[3] = key[3];
            p[4] = key[4];
            p[5] = key[5];
            p[6] = key[6];
            p[7] = key[7];

            for (u64 i = 0; i < 3; ++i)
            {
                t[0] = _mm_slli_si128(p[0], 4);
                t[1] = _mm_slli_si128(p[1], 4);
                t[2] = _mm_slli_si128(p[2], 4);
                t[3] = _mm_slli_si128(p[3], 4);
                t[4] = _mm_slli_si128(p[4], 4);
                t[5] = _mm_slli_si128(p[5], 4);
                t[6] = _mm_slli_si128(p[6], 4);
                t[7] = _mm_slli_si128(p[7], 4);

                p[0] = _mm_xor_si128(p[0], t[0]);
                p[1] = _mm_xor_si128(p[1], t[1]);
                p[2] = _mm_xor_si128(p[2], t[2]);
                p[3] = _mm_xor_si128(p[3], t[3]);
                p[4] = _mm_xor_si128(p[4], t[4]);
                p[5] = _mm_xor_si128(p[5], t[5]);
                p[6] = _mm_xor_si128(p[6], t[6]);
                p[7] = _mm_xor_si128(p[7], t[7]);
            }

            key[0] = _mm_xor_si128(p[0], keyRcon[0]);
            key[1] = _mm_xor_si128(p[1], keyRcon[1]);
            key[2] = _mm_xor_si128(p[2], keyRcon[2]);
            key[3] = _mm_xor_si128(p[3], keyRcon[3]);
            key[4] = _mm_xor_si128(p[4], keyRcon[4]);
            key[5] = _mm_xor_si128(p[5], keyRcon[5]);
            key[6] = _mm_xor_si128(p[6], keyRcon[6]);
            key[7] = _mm_xor_si128(p[7], keyRcon[7]);
        };
#endif

        // Set the N keys to be used for encryption.
        void setKeys(span<block> keys)
        {
#ifdef OC_ENABLE_AESNI
            constexpr u64 main = N / 8 * 8;

            auto cp = [&](u8 i, AES* aes, std::array<block, 8>& buff)
            {
                aes[0].mRoundKey[i] = buff[0];
                aes[1].mRoundKey[i] = buff[1];
                aes[2].mRoundKey[i] = buff[2];
                aes[3].mRoundKey[i] = buff[3];
                aes[4].mRoundKey[i] = buff[4];
                aes[5].mRoundKey[i] = buff[5];
                aes[6].mRoundKey[i] = buff[6];
                aes[7].mRoundKey[i] = buff[7];
            };
            std::array<block, 8> buff;

            for (u64 i = 0; i < main; i += 8)
            {
                auto* aes = &mAESs[i];

                buff[0] = keys[i + 0];
                buff[1] = keys[i + 1];
                buff[2] = keys[i + 2];
                buff[3] = keys[i + 3];
                buff[4] = keys[i + 4];
                buff[5] = keys[i + 5];
                buff[6] = keys[i + 6];
                buff[7] = keys[i + 7];
                cp(0, aes, buff);

                keyGenHelper8<0x01>(buff);
                cp(1, aes, buff);
                keyGenHelper8<0x02>(buff);
                cp(2, aes, buff);
                keyGenHelper8<0x04>(buff);
                cp(3, aes, buff);
                keyGenHelper8<0x08>(buff);
                cp(4, aes, buff);
                keyGenHelper8<0x10>(buff);
                cp(5, aes, buff);
                keyGenHelper8<0x20>(buff);
                cp(6, aes, buff);
                keyGenHelper8<0x40>(buff);
                cp(7, aes, buff);
                keyGenHelper8<0x80>(buff);
                cp(8, aes, buff);
                keyGenHelper8<0x1B>(buff);
                cp(9, aes, buff);
                keyGenHelper8<0x36>(buff);
                cp(10, aes, buff);
            }
#else
            u64 main = 0;
#endif

            for (u64 i = main; i < N; ++i)
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


        // Computes the hash of N blocks pointed to by plaintext
        // and stores the result at ciphertext.
        void hashNBlocks(const block* plaintext, block* hashes) const
        {
            std::array<block, N> buff;
            for (int i = 0; i < N; ++i)
                buff[i] = plaintext[i];
            //memcpy(buff.data(), plaintext, 16 * N);
            ecbEncNBlocks(buff.data(), buff.data());
            for (int i = 0; i < N; ++i) hashes[i] = buff[i] ^ plaintext[i];
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

	// Pseudorandomly generate a stream of AES round keys.
	struct AESStream
	{
		static constexpr size_t chunkSize = 8;

		AES prng;
		MultiKeyAES<chunkSize> aesRoundKeys;
		size_t index;

		// Uninitialized.
		AESStream() = default;

		AESStream(block seed)
		{
			setSeed(seed);
		}

		void setSeed(block seed)
		{
			index = 0;
			prng.setKey(seed);
			refillBuffer();
		}

		const AES& get() const
		{
			return aesRoundKeys.mAESs[index % chunkSize];
		}

		void next()
		{
			if (++index % chunkSize == 0)
				refillBuffer();
		}

		void refillBuffer()
		{
			std::array<block, chunkSize> keys;
			prng.ecbEncCounterMode(index, keys);
			aesRoundKeys.setKeys(keys);
		}
	};


    // An AES instance with a fixed and public key.
    extern const AES mAesFixedKey;


}
