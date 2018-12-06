#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <type_traits>
#include <cryptoTools/Crypto/blake2/blake2.h>
#include <cstring>

namespace osuCrypto {

	// An implementation of Blake 2
	class Blake2
	{
	public:
		// The default size of the blake digest output by Final(...);
		static const u64 HashSize = 20;

		// The maximum size of the blake digest output by Fianl(...);
		static const u64 MaxHashSize = BLAKE2B_OUTBYTES;

		// Default constructor of the class. Initializes the internal state.
		Blake2(u64 outputLength = HashSize) { Reset(outputLength); }

		// Resets the interal state.
		void Reset()
		{
			Reset(outputLength());
		}

		// Resets the interal state.
		void Reset(u64 outputLength)
		{
	
#ifdef TRUE_BLAKE2_INIT
			Expects(blake2b_init(&state, outputLength) == 0);
#else
			const uint64_t blake2b_IV[8] =
			{
				0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
				0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
				0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
				0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
			};

			const unsigned char * v = (const unsigned char *)(blake2b_IV);
			std::memset(&state, 0, sizeof(blake2b_state));
			state.outlen = outputLength;
            std::memcpy(state.h, v, BLAKE2B_OUTBYTES);
#endif
	}

		// Add length bytes pointed to by dataIn to the internal Blake2 state.
		template<typename T>
		typename std::enable_if<std::is_pod<T>::value>::type Update(const T* dataIn, u64 length)
		{
			Expects(blake2b_update(&state, dataIn, length * sizeof(T)) == 0);
		}

		template<typename T>
		typename std::enable_if<std::is_pod<T>::value>::type Update(const T& blk)
		{
			Update((u8*)&blk, sizeof(T));
		}

		// Finalize the Blake2 hash and output the result to DataOut.
		// Required: DataOut must be at least outputLength() bytes long.
		void Final(u8* DataOut)
		{
			Expects(blake2b_final(&state, DataOut, state.outlen) == 0);
		}

		// Finalize the Blake2 hash and output the result to out. 
		// Only sizeof(T) bytes of the output are written.
		template<typename T>
		typename std::enable_if<std::is_pod<T>::value && sizeof(T) <= MaxHashSize && std::is_pointer<T>::value == false>::type
			Final(T& out)
		{
			if (sizeof(T) != outputLength())
				throw std::runtime_error(LOCATION);
			Final((u8*)&out);
		}

		// Copy the interal state of a Blake2 computation.
		const Blake2& operator=(const Blake2& src);

		// returns the number of bytes that will be written when Final(...) is called.
		u64 outputLength() const
		{
			return state.outlen;
		}
	private:
		blake2b_state state;

		static blake2b_state _start_state;
};
}
