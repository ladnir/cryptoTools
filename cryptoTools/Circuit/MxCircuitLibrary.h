#pragma once
#include "cryptoTools/Common/Matrix.h"
#include "MxBit.h"

namespace osuCrypto
{
	namespace Mx
	{


		enum class Optimized
		{
			Size,
			Depth
		};

		enum class IntType
		{
			TwosComplement,
			Unsigned
		};
		enum class AdderType
		{
			Addition,
			Subtraction
		};

		// takes a integer `a` as input. If `it` is twos complement, then we 
		// append the MSB of `a` until it is `size` bits. Otherwise we append
		// 0.
		inline std::vector<Bit> signExtendResize(span<const Bit> a, u64 size, IntType it)
		{
			std::vector<Bit> b(a.begin(), a.end());
			if (it == IntType::TwosComplement)
			{
				while (b.size() < size)
					b.push_back(b.back());
			}
			else
			{
				while (b.size() < size)
					b.push_back(Bit(0));
			}
			b.resize(size);
			return b;
		}

		// add or substracts a1 and a2. Does this with O(n log n) AND gates.
		// and O(log n) depth.
		void parallelPrefix(
			span<const Bit> a1,
			span<const Bit> a2,
			span<Bit> sum,
			IntType it,
			AdderType at);

		// compare a1 and a2 for equality. Must be the same size.
		Bit parallelEquality(span<const Bit> a1, span<const Bit> a2);

	}

}