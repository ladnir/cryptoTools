#pragma once
#include "cryptoTools/Common/Defines.h"
#ifdef ENABLE_CIRCUITS

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

		// ripple carry adder with parameters
		// a1, a2 and carry in cIn. The output 
		// is sum = a1[i] ^ a2[i] ^ cIn
		// and the carry out bit cOut. Works 
		// for addition and subtraction.
		void rippleAdder(
			const Bit& a1,
			const Bit& a2,
			const Bit& cIn,
			Bit& sum,
			Bit& cOut,
			AdderType at);

		// ripple carry adder with parameters
		// a1, a2. The output 
		// is sum = a1+a2. Works 
		// for addition and subtraction.
		void rippleAdder(
			span<const Bit> a1,
			span<const Bit> a2,
			span<Bit> sum,
			IntType it,
			AdderType at);


		// compute the summation x[0] + x[1] + ...
		void parallelSummation(
			span<span<const Bit>> x,
			span<Bit> sum,
			Optimized op,
			IntType it
		);

		// computes dst = a1 * a2;
		void multiply(
			span<const Bit> a1, 
			span<const Bit> a2, 
			span<Bit> dst,
			Optimized op,
			IntType it);
	}

}
#endif
