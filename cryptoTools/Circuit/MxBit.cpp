#include "MxBit.h"
#ifdef ENABLE_CIRCUITS

#include "MxCircuit.h"

namespace osuCrypto
{

    namespace Mx
    {

		Bit::~Bit()
		{
			if (isConst() == false)
				circuit()->remove(*this);
		}

		Bit& Bit::operator=(const Bit& o)
		{
			if (o.isConst())
			{
				if (isConst() == false)
					circuit()->remove(*this);
				mCir = o.mCir;
			}
			else
			{
				o.circuit()->copy(o, *this);
			}

			return *this;
		}

		Bit& Bit::operator=(Bit&& o)
		{
			if (o.isConst() == false)
			{
				o.circuit()->move(std::move(o), *this);
			}
			else 
			{
				if (isConst() == false)
					circuit()->remove(*this);
				mCir = o.mCir;
			}

			o.mCir = nullptr;
			return *this;
		}


		Bit& Bit::operator=(bool b)
		{
			mCir = (Circuit*)(b ? 1ull : 0ull);
			return *this;
		}


		Bit Bit::operator^(const Bit& b)const
		{
			return addGate(OpType::Xor, b);
		}
		Bit Bit::operator&(const Bit& b)const
		{
			return addGate(OpType::And, b);
		}
		Bit Bit::operator|(const Bit& b)const
		{
			return addGate(OpType::Or, b);
		}
		Bit Bit::operator!() const
		{
			if (isConst())
			{
				Bit r;
				r.mCir = (Circuit*)((u64)mCir ^ 1);
				return r;
			}

			return circuit()->negate(*this);
		}
		Bit Bit::operator~() const
		{
			return !*this;
		}

		Bit Bit::addGate(OpType t, const Bit& b) const
		{

			if (isConst() || b.isConst())
			{
				if (isConst() && b.isConst())
				{
					switch (t)
					{
					case osuCrypto::Mx::OpType::Xor:
						return constValue() ^ b.constValue();
					case osuCrypto::Mx::OpType::And:
						return constValue() && b.constValue();
					case osuCrypto::Mx::OpType::Or:
						return constValue() || b.constValue();
					default:
						throw std::runtime_error("Bit::addGate(...) for OpType that is not implemented. " LOCATION);
					}
				}
				else
				{
					auto c = isConst() ? constValue() : b.constValue();
					auto& w = isConst() ? b : *this;
					auto cir = isConst() ? b.circuit() : circuit();

					switch (t)
					{
					case osuCrypto::Mx::OpType::Xor:
						return c ? cir->negate(w) : w;
					case osuCrypto::Mx::OpType::And:
						return c ? w : 0;
					case osuCrypto::Mx::OpType::Or:
						return c ? 1 : w;
					default:
						throw std::runtime_error("Bit::addGate(...) for OpType that is not implemented. " LOCATION);
					}
				}
			}

			return circuit()->addGate(t, *this, b);
		}
    }

}
#endif
