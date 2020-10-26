#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>

namespace osuCrypto {

    namespace details
    {
        enum Rijndael256Types
        {
            NI,
            Portable
        };

        static const int rijndael256_rounds = 14;

        template<Rijndael256Types types>
        class Rijndael256Enc
        {
        public:
            using Block = std::array<block, 2>;
            static const int rounds = rijndael256_rounds;
            std::array<Block, rounds + 1> mRoundKey;

            // Default constructor leaves the class in an invalid state
            // until setKey(...) is called.
            Rijndael256Enc() = default;
            Rijndael256Enc(const Rijndael256Enc&) = default;

            // Constructor to initialize the class with the given key
            Rijndael256Enc(const Block& userKey)
            {
                setKey(userKey);
            }

            // Set the key to be used for encryption.
            void setKey(const Block& userKey);

            Block encBlock(Block plaintext) const;

            static Block roundEnc(Block state, const Block& roundKey);
            static Block finalEnc(Block state, const Block& roundKey);
        };

        template<Rijndael256Types type>
        class Rijndael256Dec
        {
        public:
            using Block = std::array<block, 2>;
            static const int rounds = rijndael256_rounds;
            std::array<Block, rounds + 1> mRoundKey;

            Rijndael256Dec() = default;
            Rijndael256Dec(const Rijndael256Dec&) = default;

            Rijndael256Dec(const Rijndael256Enc<type>& enc)
            {
                setKey(enc);
            }

            Rijndael256Dec(const Block& userKey)
            {
                setKey(userKey);
            }

            void setKey(const Block& userKey)
            {
                setKey(Rijndael256Enc<NI>(userKey));
            }

            void setKey(const Rijndael256Enc<type>& enc);

            Block decBlock(const Block ciphertext) const;

            static Block roundDec(Block state, const Block& roundKey);
            static Block finalDec(Block state, const Block& roundKey);
        };
    }

#ifdef OC_ENABLE_AESNI
    using Rijndael256Enc = details::Rijndael256Enc<details::NI>;
    using Rijndael256Dec = details::Rijndael256Dec<details::NI>;
#else
    using Rijndael256Enc = details::Rijndael256Enc<details::Portable>;
    using Rijndael256Dec = details::Rijndael256Dec<details::Portable>;
#endif

    // TODO: encryption of N values under N different keys
}
