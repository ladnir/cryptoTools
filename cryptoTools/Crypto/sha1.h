#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <type_traits>

extern void sha1_compress(uint32_t state[5], const uint8_t block[64]);

namespace osuCrypto {

	// An implementation of SHA1 based on Intel assembly code
    class SHA1
    {
    public:
		// The size of the SHA digest output by Final(...);
        static const u64 HashSize = 20;

		// Default constructor of the class. Sets the internal state to zero.
		SHA1() { Reset(); }

		// Resets the interal state.
		void Reset()
		{
			memset(this, 0, sizeof(SHA1));
		}

		// Add length bytes pointed to by dataIn to the internal SHA1 state.
		void Update(const u8* dataIn, u64 length)
		{
			while (length)
			{
				u64 step = std::min<u64>(length, u64(64) - idx);
				memcpy(buffer.data() + idx, dataIn, step);

				idx += step;
				dataIn += step;
				length -= step;

				if (idx == 64)
				{
					sha1_compress(state.data(), buffer.data());
					idx = 0;
				}
			}
		}

		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value> Update(const T& blk)
		{
			Update((u8*)&blk, sizeof(T));
		}

		// Finalize the SHA1 hash and output the result to DataOut.
		// Required: DataOut must be at least SHA1::HashSize in length.
		void Final(u8* DataOut, u64 length  = sizeof(u32) * 5)
		{
#ifndef NDEBUG 
			if (length > sizeof(u32) * 5) throw std::runtime_error(LOCATION);
#endif

			if (idx) sha1_compress(state.data(), buffer.data());
			idx = 0;
			memcpy(DataOut, state.data(), length);
		}

		// Finalize the SHA1 hash and output the result to out. 
		// Only sizeof(T) bytes of the output are written.
		template<typename T>
		typename std::enable_if_t<std::is_pod<T>::value && sizeof(T) <= HashSize>
			Final(T& out)
		{
			Final((u8*)&out, sizeof(T));
		}

		// Copy the interal state of a SHA1 computation.
        const SHA1& operator=(const SHA1& src);

    private:
        std::array<uint32_t,5> state;
        std::array<uint8_t, 64> buffer;
        u64 idx;
    };
}
