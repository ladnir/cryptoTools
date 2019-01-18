#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <type_traits>
#include <cstring>

extern void sha1_compress(uint32_t state[5], const uint8_t block[64]);

namespace osuCrypto {

	// An implementation of SHA1 based on Intel assembly code
    class SHA1
    {
    public:
		// The size of the SHA digest output by Final(...);
        static const u64 HashSize = 20;

		// Default constructor of the class. Sets the internal state to zero.
		SHA1(u64 outputLenght = HashSize) { Reset(outputLenght); }

		// Resets the interal state.
		void Reset()
		{
			Reset(outputLength());
		}

		// Resets the interal state and sets the desired output length in bytes.
		void Reset(u64 digestByteLenght)
		{
			memset(this, 0, sizeof(SHA1));
			outputLenght = u32(digestByteLenght);
		}

		// Add length bytes pointed to by dataIn to the internal Blake2 state.
		template<typename T>
		typename std::enable_if<std::is_pod<T>::value>::type Update(const T* dd, u64 ll)
		{
			auto length = ll * sizeof(T);
			u8* dataIn = (u8*)dd;

			while (length)
			{
				u32 step = u32(std::min<u64>(length, 64ull - idx));
				std::memcpy(buffer.data() + idx, dataIn, step);

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
		typename std::enable_if<std::is_pod<T>::value && !std::is_pointer<T>::value>::type Update(const T& blk)
		{
			Update((u8*)&blk, sizeof(T));
		}

		// Finalize the SHA1 hash and output the result to DataOut.
		// Required: DataOut must be at least SHA1::HashSize in length.
		void Final(u8* DataOut)
		{
			if (idx) sha1_compress(state.data(), buffer.data());
			idx = 0;
            std::memcpy(DataOut, state.data(), outputLength());
		}


		// Finalize the SHA1 hash and output the result to out. 
		// Only sizeof(T) bytes of the output are written.
		template<typename T>
		typename std::enable_if<std::is_pod<T>::value && sizeof(T) <= HashSize && std::is_pointer<T>::value == false>::type
			Final(T& out)
		{
#ifndef NDEBUG
			if (sizeof(T) != outputLength())
				throw std::runtime_error(LOCATION);
#endif
			Final((u8*)&out);
		}

		// Copy the interal state of a SHA1 computation.
        const SHA1& operator=(const SHA1& src);

		u64 outputLength() const { return  outputLenght; }

    private:
        std::array<uint32_t,5> state;
        std::array<uint8_t, 64> buffer;
        u32 idx, outputLenght;
    };
}
