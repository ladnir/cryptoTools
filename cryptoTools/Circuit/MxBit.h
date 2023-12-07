#pragma once
#include "cryptoTools/Common/Defines.h"
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

			Add = 16,
			Mult = 17,
			Sub = 18,

			BinToArth = 20,
			ArthToBin = 21,

			Print = 22

		};

		struct Gate
		{

			std::array<u64, 2> mInput;
			u64 mOutput;
			OpType mType;
		};


		struct Bit
		{
			using representation_type = Bit;

			Circuit* mCir = nullptr;
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
			Circuit* circuit() const;
			bool isConst() const;
			bool constValue() const;
			Bit& operator=(const Bit& o);
			Bit& operator=(Bit&& o);
			Bit& operator=(bool b);
			Bit operator^(const Bit& b)const;
			Bit operator&(const Bit& b)const;
			Bit operator|(const Bit& b)const;
			Bit operator!() const;
			Bit operator~() const;

			Bit addGate(OpType t, const Bit& b) const;

			bool operator==(bool b) const
			{
				return isConst() && constValue() == b;
			}

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