#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>

extern void sha1_compress(uint32_t state[5], const uint8_t block[64]);

namespace osuCrypto {

	// An implementation of SHA1 based on Intel assembly code
    class SHA1
    {
    public:
		// The size of the SHA digest output by Final(...);
        static const u64 HashSize = 20;

		// Default constructor of the class. Sets the internal state to zero.
        SHA1();

		// Resets the interal state.
        void Reset();

		// Add length bytes pointed to by dataIn to the internal SHA1 state.
        void Update(const u8* dataIn, u64 length);

		// Add the block to the internal SHA1 state.
        void Update(const block& blk);

		// Finalize the SHA1 hash and output the result to DataOut.
		// Required: DataOut must be at least SHA1::HashSize in length.
        void Final(u8* DataOut);

		// Finalize the SHA1 hash and output the result to out. 
		// Only sizeof(block) bytes of the output are written.
        void Final(block& out);

		// Copy the interal state of a SHA1 computation.
        const SHA1& operator=(const SHA1& src);

    private:
        std::array<uint32_t,5> state;
        std::array<uint8_t, 64> buffer;
        u64 idx;
    };
}
