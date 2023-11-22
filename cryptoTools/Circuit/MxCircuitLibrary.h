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


		void parallelPrefix(
			span<const Bit> a1,
			span<const Bit> a2,
			span<Bit> sum,
			IntType it,
			AdderType at);
	}

}