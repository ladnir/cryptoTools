
#pragma once
#include "cryptoTools/Common/Defines.h"
#include "MxBit.h"
#include <unordered_map>
#include "macoro/optional.h"
#include "macoro/variant.h"

namespace osuCrypto
{
	namespace Mx
	{
		class LeveledCircuit
		{

		};

		class Circuit
		{
		public:

			enum ValueType
			{
				Binary,
				Z2k
			};

			// wire address or value.
			struct Wire : macoro::variant<u64, bool>
			{
				bool isAddress() const { return index() == 0; }
				bool isConst() const { return !isAddress(); }

				bool value() const {
					if (isAddress())
						throw RTE_LOC;
					return std::get<1>(*this);
				}

				u64 address() const {

					if (isConst())
						throw RTE_LOC;
					return std::get<0>(*this);
				}

			};

			struct IO
			{
				std::vector<Wire> mWires;
			};

			struct Print
			{
				std::function<std::string(const BitVector& b)> mFn;
				std::vector<Wire> mWires;
			};

			std::vector<IO> mInputs, mOutputs;
			std::unordered_map<const Bit*, u64> mBitMap;

			template <typename T, typename ... Args>
			T input(Args...);

			template <typename T>
			void output(T&);

			u64 mNextBitIdx = 0;
			u64 addBitMap(Bit& b) {
				auto iter = mBitMap.find(&b);
				if (iter == mBitMap.end())
				{
					auto idx = mNextBitIdx++;
					mBitMap.insert({ &b, idx });
					b.mCir = this;
					return idx;
				}
				else
					throw std::runtime_error("internal error: bit has already been mapped. " LOCATION);
			}

			u64 getBitMap(const Bit& b) {
				auto iter = mBitMap.find(&b);
				if (iter == mBitMap.end())
				{
					throw std::runtime_error("error: reading an uninitilized value. " LOCATION);
				}
				else
					return iter->second;
			}

			std::vector<Gate> mGates;
			std::vector<Print> mPrints;

			void addPrint(Print&& p)
			{
				Gate g;
				g.mInput[0] = mPrints.size();
				g.mType = OpType::Print;
				mGates.push_back(g);

				mPrints.push_back(std::move(p));
			}

			Bit addGate(OpType t, const Bit& a, const Bit& b)
			{
				Bit ret;
				Gate g;
				g.mInput[0] = getBitMap(a);
				g.mInput[1] = getBitMap(b);
				g.mOutput = addBitMap(ret);
				g.mType = t;
				mGates.push_back(g);
				return ret;
			}

			void copy(const Bit& a, Bit& d)
			{
				if (mBitMap.find(&d) == mBitMap.end())
					addBitMap(d);
				Gate g;
				g.mInput[0] = getBitMap(a);
				g.mOutput = getBitMap(d);
				g.mType = OpType::a;
				mGates.push_back(g);
			}

			void move(Bit&& a, Bit& d)
			{
				auto iter = mBitMap.find(&a);
				if (iter == mBitMap.end())
					throw std::runtime_error("uninitialized bit was moved. " LOCATION);
				auto idx = iter->second;

				if (mBitMap.find(&d) != mBitMap.end())
					remove(d);

				mBitMap[&d] = idx;
				d.mCir = this;
				mBitMap.erase(iter);
			}

			void remove(Bit& a)
			{
				auto iter = mBitMap.find(&a);
				if (iter == mBitMap.end())
					throw std::runtime_error("uninitialized bit was removed. " LOCATION);
				mBitMap.erase(iter);
			}

			Bit negate(const Bit& a)
			{
				Bit d;
				addBitMap(d);
				Gate g;
				g.mInput[0] = getBitMap(a);
				g.mOutput = getBitMap(d);
				g.mType = OpType::na;
				mGates.push_back(g);
				return d;
			}


			void evaluate(const std::vector<BitVector>& in, std::vector<BitVector>& out)
			{
				if (in.size() != mInputs.size())
					throw std::runtime_error("MxCircuit::evaluate(...), number of inputs provided is not correct. " LOCATION);

				std::vector<u8> vals(mNextBitIdx);

				for (u64 i = 0; i < in.size(); ++i)
				{
					if (in[i].size() != mInputs[i].mWires.size())
						throw std::runtime_error("MxCircuit::evaluate(...), the i'th input provided is not the correct size. " LOCATION);

					for (u64 j = 0; j < in[i].size(); ++j)
					{
						u64 address = std::get<0>(mInputs[i].mWires[j]);
						vals[address] = in[i][j];
					}
				}

				for (u64 i = 0; i < mGates.size(); ++i)
				{
					auto gate = mGates[i];
					switch (gate.mType)
					{
					case OpType::a:
						vals[gate.mOutput] = vals[gate.mInput[0]];
						break;
					case OpType::na:
						vals[gate.mOutput] = !vals[gate.mInput[0]];
						break;
					case OpType::And:
						vals[gate.mOutput] = vals[gate.mInput[0]] & vals[gate.mInput[1]];
						break;
					case OpType::Or:
						vals[gate.mOutput] = vals[gate.mInput[0]] | vals[gate.mInput[1]];
						break;
					case OpType::Xor:
						vals[gate.mOutput] = vals[gate.mInput[0]] ^ vals[gate.mInput[1]];
						break;
					case OpType::Print:
					{
						auto& p = mPrints[gate.mInput[0]];
						BitVector v(p.mWires.size());
						for (u64 j = 0; j < v.size(); ++j)
						{
							if (p.mWires[j].isAddress())
								v[j] = vals[p.mWires[j].address()];
							else
								v[j] = p.mWires[j].value();
						}
						std::cout << p.mFn(v);
						break;
					}
					default:
						throw std::runtime_error("MxCircuit::evaluate(...), gate type not implemented. " LOCATION);
						break;
					}
				}


				out.resize(mOutputs.size());
				for (u64 i = 0; i < out.size(); ++i)
				{
					out[i].resize(mOutputs[i].mWires.size());

					for (u64 j = 0; j < out[i].size(); ++j)
					{

						if (mOutputs[i].mWires[j].isAddress())
							out[i][j] = vals[mOutputs[i].mWires[j].address()];
						else
							out[i][j] = mOutputs[i].mWires[j].value();
					}
				}
			}

		};


		template<typename T, typename = void>
		struct has_bit_representation_type : std::false_type
		{};

		template <typename T>
		struct has_bit_representation_type <T, std::void_t<
			// must have value_type
			typename std::remove_reference_t<T>::representation_type,

			// must be trivial
			std::enable_if_t<
			std::is_same<
			typename std::remove_reference_t<T>::representation_type,
			Bit
			>::value
			>
			>>
			: std::true_type{};


		template<typename T>
		inline typename std::enable_if<
			has_bit_representation_type<T>::value == true
			, Circuit&>::type operator<<(Circuit& o, T&& t)
		{
			Circuit::Print p;
			auto elems = t.serialize();
			p.mWires.reserve(elems.size());
			for (auto e : elems)
			{
				if (e->isConst())
					p.mWires.push_back(Circuit::Wire{ e->constValue() });
				else
					p.mWires.push_back(Circuit::Wire{ o.getBitMap(*e) });
			}
			p.mFn = t.toString();
			o.addPrint(std::move(p));
			return o;
		}


		template<typename T>
		inline typename std::enable_if<
			has_bit_representation_type<T>::value == false
			, Circuit&>::type operator<<(Circuit& o, T&& t)
		{
			Circuit::Print p;
			p.mFn = [t = std::forward<T>(t)](const BitVector&)
				{
					std::stringstream ss;
					ss << t;
					return ss.str();
				};
			o.addPrint(std::move(p));
			return o;
		}

		template<typename T, typename ...Args>
		inline T Circuit::input(Args ... args)
		{
			//Input in;
			T input(std::forward<Args>(args)...);
			auto elems = input.deserialize();
			IO in;
			for (auto& e : elems)
			{
				//if (e->isConst())
				//	in.mWires.push_back(Wire{ e->constValue() });
				//else
				in.mWires.push_back(Wire{ addBitMap(*e) });
			}

			mInputs.push_back(std::move(in));
			return input;
		}

		template<typename T>
		inline void Circuit::output(T& o)
		{
			//Input in;
			auto elems = o.serialize();
			IO out;
			for (auto& e : elems)
			{
				if (e->isConst())
					out.mWires.push_back(Wire{ e->constValue() });
				else
					out.mWires.push_back(Wire{ getBitMap(*e) });
			}

			mOutputs.push_back(std::move(out));
		}


	}
}