#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>
#include <type_traits>
#ifdef ENABLE_SSE_BLAKE2
#include <cryptoTools/Crypto/blake2/sse/blake2.h>
#else
#include <cryptoTools/Crypto/blake2/c/blake2.h>
#endif
#include <cstring>

#include "Hashable.h"

namespace osuCrypto {

	// An implementation of Blake 2
	class Blake2
	{
	public:
		// The default size of the blake digest output by Final(...);
		static const u64 HashSize = 20;

		// The maximum size of the blake digest output by Final(...);
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
			blake2b_init(&state, outputLength);
		}

		// Add length bytes pointed to by dataIn to the internal Blake2 state.
		template<typename T>
		typename std::enable_if<
			std::is_standard_layout<T>::value&&
			std::is_trivial<T>::value
		>::type Update(const T* dataIn, u64 length)
		{
			blake2b_update(&state, dataIn, length * sizeof(T));
		}

		template<typename T>
		typename std::enable_if<Hashable<T>::value>::type Update(const T& t)
		{
			Hashable<T>::hash(t, *this);
		}

		// Finalize the Blake2 hash and output the result to DataOut.
		// Required: DataOut must be at least outputLength() bytes long.
		void Final(u8* DataOut)
		{
			blake2b_final(&state, DataOut, state.outlen);
		}

		// Finalize the Blake2 hash and output the result to out.
		// Only sizeof(T) bytes of the output are written.
		template<typename T>
		typename std::enable_if<
			std::is_standard_layout<T>::value&&
			std::is_trivial<T>::value &&
			sizeof(T) <= MaxHashSize && 
			std::is_pointer<T>::value == false
		>::type
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
	};
}
