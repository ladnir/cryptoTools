#pragma once
#include "cryptoTools/Common/Defines.h"
#include "MxCircuit.h"
#include <vector>
#include <array>
#include "MxCircuitLibrary.h"
#include "cryptoTools/Common/BitVector.h"

namespace osuCrypto
{
	namespace Mx
	{
		inline std::string intFromBits(const oc::BitVector& b)
		{
			if (b.size() > 64)
				throw std::runtime_error("not implemented. " LOCATION);
			i64 v = 0;
			for (u64 i = 0; i < b.size(); ++i)
			{
				v |= u64(b[i]) << i;
			}
			for (u64 i = b.size(); i < 64; ++i)
			{
				v |= u64(b[b.size() - 1]) << i;
			}
			return std::to_string(v);
		}

		template<u64 n>
		struct BitArray
		{
			using base_type = Bit;
			static const u64 mSize = n;
			std::array<Bit, n> mBits;

			BitArray() = default;
			BitArray(const BitArray&) = default;
			BitArray(BitArray&&) = default;
			BitArray& operator=(const BitArray&) = default;
			BitArray& operator=(BitArray&&) = default;

			BitArray operator^(const BitArray& b)const
			{
				BitArray r;
				for (u64 i = 0; i < size(); ++i)
					r.mBits[i] = mBits[i] ^ b.mBits[i];
				return r;
			}

			BitArray operator&(const BitArray& b)const
			{
				BitArray r;
				for (u64 i = 0; i < size(); ++i)
					r.mBits[i] = mBits[i] & b.mBits[i];
				return r;
			}

			BitArray operator~() const
			{
				BitArray r;
				for (u64 i = 0; i < size(); ++i)
					r.mBits[i] = ~mBits[i];
				return r;
			}

			static constexpr u64 size() { return mSize; }
			Bit& operator[](u64 i) { return mBits[i]; }
			const Bit& operator[](u64 i) const { return mBits[i]; }

			Bit* begin() { return mBits.data(); }
			Bit* end() { return mBits.data() + mBits.size(); }

			const Bit* begin() const { return mBits.data(); }
			const Bit* end() const { return mBits.data() + mBits.size(); }

			static std::string strFromBits(const BitVector& b) {
				std::stringstream ss;
				ss << b;
				return ss.str();
			}
		};

		struct BVector
		{
			using base_type = Bit;
			std::vector<Bit> mBits;

			BVector() = default;
			BVector(const BVector&) = default;
			BVector(BVector&&) = default;
			BVector& operator=(const BVector&) = default;
			BVector& operator=(BVector&&) = default;

			BVector(u64 n)
			{
				resize(n);
			}

			BVector operator^(const BVector& b)const
			{
				BVector r;
				for (u64 i = 0; i < size(); ++i)
					r.mBits[i] = mBits[i] ^ b.mBits[i];
				return r;
			}

			BVector operator&(const BVector& b)const
			{
				BVector r;
				for (u64 i = 0; i < size(); ++i)
					r.mBits[i] = mBits[i] & b.mBits[i];
				return r;
			}

			BVector operator~() const
			{
				BVector r;
				for (u64 i = 0; i < size(); ++i)
					r.mBits[i] = ~mBits[i];
				return r;
			}


			u64 size() const { return mBits.size(); }
			Bit& operator[](u64 i) { return mBits[i]; }
			const Bit& operator[](u64 i) const { return mBits[i]; }

			Bit* begin() { return mBits.data(); }
			Bit* end() { return mBits.data() + mBits.size(); }

			const Bit* begin() const { return mBits.data(); }
			const Bit* end() const { return mBits.data() + mBits.size(); }

			void resize(u64 n)
			{
				mBits.resize(n);
			}

			void clear()
			{
				mBits.clear();
			}


			static std::string strFromBits(const oc::BitVector& b) {
				std::stringstream ss;
				ss << b;
				return ss.str();
			}
		};

		template<u64 n>
		struct BInt : public BitArray<n>
		{
			using base_type = Bit;
			BInt() = default;
			BInt(const BInt&) = default;
			BInt(BInt&&) = default;
			BInt& operator=(const BInt&) = default;
			BInt& operator=(BInt&&) = default;

			BInt(i64 v)
			{
				*this = v;
			}

			BInt& operator=(i64 v)
			{
				for (u64 i = 0; i < size(); ++i)
				{
					mBits[i] = v & 1;
					v >>= 1;
				}
				return *this;
			}

			BInt operator+(const BInt& b)const
			{
				BInt r;
				parallelPrefix(mBits, b.mBits, r.mBits,IntType::TwosComplement,AdderType::Subtraction);
				return r;
			}

			BInt operator-(const BInt& b)const
			{
				BInt r;
				parallelPrefix(mBits, b.mBits, r.mBits,IntType::TwosComplement,AdderType::Subtraction);
				return r;
			}

			static std::string strFromBits(const oc::BitVector& b) { return intFromBits(b); }
		};

		template<>
		struct BInt<0> : public BVector
		{
			using base_type = Bit;
			BInt() = default;
			BInt(const BInt&) = default;
			BInt(BInt&&) = default;
			BInt& operator=(const BInt&) = default;
			BInt& operator=(BInt&&) = default;

			BInt operator+(const BInt& b)const
			{
				BInt r;
				parallelPrefix(mBits, b.mBits, r.mBits, IntType::TwosComplement, AdderType::Addition);
				return r;
			}

			BInt operator-(const BInt& b)const
			{
				BInt r;
				parallelPrefix(mBits, b.mBits, r.mBits, IntType::TwosComplement, AdderType::Subtraction);
				return r;
			}
			static std::string strFromBits(const oc::BitVector& b) { return intFromBits(b); }
		};

	}
}