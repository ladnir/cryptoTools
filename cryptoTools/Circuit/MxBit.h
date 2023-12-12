#pragma once
#include "cryptoTools/Common/Defines.h"
#ifdef ENABLE_CIRCUITS

#include "cryptoTools/Common/BitVector.h"
#include <functional>
#include <sstream>

namespace osuCrypto
{
	namespace Mx
	{

		class Circuit;

		enum class OpType {

			Zero = 0,   //0000,
			Nor = 1,    //0001
			nb_And = 2, //0010
			nb = 3,     //0011
			na_And = 4, //0100
			na = 5,     //0101
			Xor = 6,    //0110
			Nand = 7,   //0111
			And = 8,    //1000
			Nxor = 9,   //1001
			a = 10,     //1010
			nb_Or = 11, //1011
			b = 12,     //1100
			na_Or = 13, //1101
			Or = 14,    //1110
			One = 15,   //1111
			Other
		};


		inline bool isLinear(OpType type)
		{
			return
				type == OpType::Xor ||
				type == OpType::Nxor ||
				type == OpType::a ||
				type == OpType::Zero ||
				type == OpType::nb ||
				type == OpType::na ||
				type == OpType::b ||
				type == OpType::One;
		}


		struct OpData
		{
			virtual ~OpData() {}
		};

		template<typename T, int S>
		struct SmallVector
		{
			std::array<T, S> mBuff;
			std::vector<T> mPtr;
			u64 mSize = 0;

			SmallVector() = default;
			SmallVector(SmallVector&& m)
			{
				mBuff = m.mBuff;
				mSize = m.mSize;
				mPtr = std::move(m.mPtr);
			}

			T& operator[](u64 i)
			{
				if (i >= mSize)
					throw RTE_LOC;
				if (isSmall())
					return mBuff[i];
				else
					return mPtr[i];
			}

			const T& operator[](u64 i)const
			{
				if (i >= mSize)
					throw RTE_LOC;
				if (isSmall())
					return mBuff[i];
				else
					return mPtr[i];
			}

			u64 capacity()
			{
				return isSmall() ? S : mPtr.capacity();
			}

			void reserve(u64 n)
			{
				if (n > capacity())
				{
					auto b = data();
					auto e = b + mSize;
					std::vector<T> vv;
					vv.reserve(n);
					vv.insert(vv.end(), b, e);
					mPtr = std::move(vv);
				}
			}

			template<typename T2>
			void push_back(T2&& v)
			{
				if (isSmall() && mSize < S)
				{
					mBuff[mSize] = v;
					++mSize;
				}
				else
				{
					if(mSize == capacity())
						reserve(mSize ? mSize * 2 : 10);
					if (mPtr.size() != size())
						throw RTE_LOC;
					mPtr.push_back(v);
					++mSize;

				}
			}

			bool isSmall() const {
				return mPtr.capacity() == 0;
			}

			T* data()
			{
				if (isSmall())
					return mBuff.data();
				else
					return mPtr.data();
			}

			u64 size() const {
				return mSize;
			}
		};

		struct Gate
		{
			SmallVector<u64, 2> mInput;
			SmallVector<u64, 1> mOutput;
			OpType mType;
			std::unique_ptr<OpData> mData;
		};


		struct Bit
		{
			using representation_type = Bit;

			Circuit* mCir = nullptr;
			u64 mAddress = -1;

			Bit() = default;
			Bit(const Bit& o)
			{
				*this = o;
			}
			Bit(Bit&& o)
			{
				*this = std::move(o);
			}
			Bit(bool v)
			{
				*this = v;
			}

			~Bit();
			Circuit* circuit() const
			{
				assert(!isConst());
				return mCir;
			}
			bool isConst() const
			{
				return ((u64)mCir <= 1);
			}
			bool constValue() const
			{
				if (isConst() == false)
					throw RTE_LOC;
				else
					return ((u64)mCir) & 1;
			}
			Bit& operator=(const Bit& o);
			Bit& operator=(Bit&& o);
			Bit& operator=(bool b);
			Bit operator^(const Bit& b)const;
			Bit operator&(const Bit& b)const;
			Bit operator|(const Bit& b)const;
			Bit operator!() const;
			Bit operator~() const;

			Bit addGate(OpType t, const Bit& b) const;

			//bool operator==(bool b) const
			//{
			//	return isConst() && constValue() == b;
			//}

			static std::function<std::string(const BitVector& b)> toString()
			{
				return [](const BitVector& b) {
					std::stringstream ss;
					ss << b;
					return ss.str();
				};
			}

			std::array<const Bit*, 1> serialize() const
			{
				return std::array<const Bit*, 1>{ { this } };
			}
			std::array<Bit*, 1> deserialize()
			{
				return std::array<Bit*, 1>{ { this } };
			}
		};



		template<u64 n>
		struct AInt
		{
			AInt() = default;
			AInt(const AInt&) = default;
			AInt(AInt&&) = default;
			AInt& operator=(const AInt&) = default;
			AInt& operator=(AInt&&) = default;

		};
	}


}
#endif