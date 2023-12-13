#pragma once
#include "cryptoTools/Common/Defines.h"
#ifdef ENABLE_CIRCUITS

#include "MxBit.h"
#include <unordered_map>
#include "macoro/optional.h"
#include "macoro/variant.h"
#include "cryptoTools/Circuit/BetaCircuit.h"

namespace osuCrypto
{
	namespace Mx
	{

		template <typename... Fs>
		struct match : Fs... {
			using Fs::operator()...;
			// constexpr match(Fs &&... fs) : Fs{fs}... {}
		};
		template<class... Ts> match(Ts...) -> match<Ts...>;

		template <typename Var, typename... Fs>
		constexpr decltype(auto) operator| (Var&& v, match<Fs...> const& match) {
			return std::visit(match, v);
		}



		class GraphCircuit
		{
		public:
			struct InputNode
			{
				//InputNode() noexcept = default;
				//InputNode(InputNode&&) noexcept = default;
				//InputNode& operator=(InputNode&&) noexcept = default;
				//InputNode(u64 i) noexcept : mIndex(i) {}

				u64 mIndex = 0;
			};

			struct OpNode
			{
				//OpNode() noexcept = default;
				//OpNode(OpNode&&) noexcept = default;
				//OpNode& operator=(OpNode&&) noexcept = default;
				//OpNode(OpType i) noexcept : mType(i) {}

				OpType mType;
			};

			struct PrintNode
			{

				using Fn = std::function<std::string(const BitVector& b)>;
				//PrintNode() noexcept = default;
				//PrintNode(PrintNode&&) noexcept = default;
				//PrintNode& operator=(PrintNode&&) noexcept = default;
				//PrintNode(Fn& f) : mFn(f) {}

				Fn* mFn;
			};

			struct OutputNode
			{

				//OutputNode() noexcept = default;
				//OutputNode(OutputNode&&) noexcept = default;
				//OutputNode& operator=(OutputNode&&) noexcept = default;
				//OutputNode(u64 i) noexcept : mIndex(i) {}

				u64 mIndex = 0;
			};

			struct Node
			{
				Node()
					: mData(InputNode{})
				{}

				//u64 level = 0;
				SmallVector<u64, 2> mInputs;
				SmallSet<u64,2> mDeps;
				SmallVector<u64, 1> mOutputs;
				SmallSet<u64, 1> mChildren;
				macoro::variant<InputNode, OpNode, PrintNode, OutputNode> mData;

				bool isLinear()
				{
					return mData | match{
						[](InputNode&) {return true; },
						[](OpNode& o) { return Mx::isLinear(o.mType); },
						[&](PrintNode&) {return mInputs.size() == 0; },
						[](OutputNode&) {return true; }
					};
				}

				void addDep(u64 d)
				{
					//if (std::find(mDeps.begin(), mDeps.end(), d) == mDeps.end())
					mDeps.insert(d);
				}

				void addChild(u64 d)
				{
					mChildren.insert(d);
					//if (std::find(mChildren.begin(), mChildren.end(), d) == mChildren.end())
				}

				void removeDep(u64 d)
				{
					mDeps.erase(d);
					//auto iter = mDeps.find(d);

					//auto iter = std::find(mDeps.begin(), mDeps.end(), d);
					//if (iter == mDeps.end())
					//	throw RTE_LOC;
					//std::swap(*iter, mDeps.back());
					//mDeps.pop_back();
				}
			};

			std::vector<Node> mNodes;
			std::vector<u64>mInputs, mOutputs;
		};

		class Circuit
		{
		public:

			Circuit() = default;
			Circuit(Circuit&&) = delete;
			Circuit(const Circuit&) = delete;

			enum ValueType
			{
				Binary,
				Z2k
			};
			// wire address or value.
			struct Wire //: macoro::variant<u64, bool>
			{
			private:
				u64 mAddress = -1;
			public:
				Wire() = default;
				Wire(u64 a) : mAddress(a)
				{}
				Wire(bool v) : mAddress(i64(-1) - v)
				{}

				bool isAddress() const { return i64(mAddress) >= 0; }
				bool isConst() const { return !isAddress(); }

				bool value() const {
					if (isAddress())
						throw RTE_LOC;
					auto v = -i64(mAddress + 1);
					assert(v < 2);
					return v;
				}



				u64 address() const {

					if (isConst())
						throw RTE_LOC;
					return mAddress;
				}

			};

			struct IO
			{
				SmallVector<Wire, 128> mWires;
			};

			struct Print : OpData
			{
				Print() = default;
				Print(const Print&) = default;
				Print(Print&&) = default;
				Print& operator=(const Print&) = default;
				Print& operator=(Print&&) = default;

				Print(
					std::function<std::string(const BitVector& b)>&& f)
					: mFn(std::move(f))
				{}

				std::function<std::string(const BitVector& b)> mFn;
			};


			std::vector<IO> mInputs, mOutputs;
			//std::unordered_map<const Bit*, u64> mBitMap;

			template <typename T, typename ... Args>
			T input(Args...);

			template <typename T>
			void output(T&);

			u64 mNextBitIdx = 0;
			u64 addBitMap(Bit& b) {
				//auto iter = mBitMap.find(&b);
				if (b.mAddress == ~0ull)
				{
					auto idx = mNextBitIdx++;
					//mBitMap.insert({ &b, idx });
					b.mCir = this;
					b.mAddress = idx;
					return idx;
				}
				else
					throw std::runtime_error("internal error: bit has already been mapped. " LOCATION);
			}

			u64 getBitMap(const Bit& b)
			{
				if (b.mAddress == ~0ull)
					throw std::runtime_error("error: reading an uninitilized value. " LOCATION);

				if (b.mAddress >= mNextBitIdx)
					throw std::runtime_error("error: bad address. " LOCATION);

				return b.mAddress;
			}

			std::vector<Gate> mGates;
			//std::vector<Print> mPrints;

			void addPrint(span<const Bit*> elems,
				std::function<std::string(const BitVector& b)>&& p)
			{
				Gate g;
				g.mType = OpType::Other;

				g.mInput.reserve(elems.size());
				std::vector<macoro::optional<bool>> consts(elems.size());
				for (u64 i = 0; i < elems.size(); ++i)
				{

					if (elems[i]->isConst() == false)
						g.mInput.push_back(getBitMap(*elems[i]));
					else
						consts[i] = elems[i]->constValue();
				}


				g.mData = std::make_unique<Print>(
					[consts = std::move(consts), f = std::move(p)](const BitVector& bv) -> std::string
					{
						BitVector v; v.reserve(consts.size());

						for (u64 i = 0, j = 0; i < consts.size(); ++i)
							if (consts[i].has_value() == false)
								v.pushBack(bv[j++]);
							else
								v.pushBack(*consts[i]);

						return f(v);
					});

				mGates.push_back(std::move(g));

			}

			Bit addGate(OpType t, const Bit& a, const Bit& b)
			{
				Bit ret;
				Gate g;
				g.mInput.push_back(getBitMap(a));
				g.mInput.push_back(getBitMap(b));
				g.mOutput.push_back(addBitMap(ret));
				g.mType = t;
				mGates.push_back(std::move(g));
				return ret;
			}

			void copy(const Bit& a, Bit& d)
			{
				if (d.mAddress == ~0ull)
					addBitMap(d);

				Gate g;
				g.mInput.push_back(getBitMap(a));
				g.mOutput.push_back(getBitMap(d));
				g.mType = OpType::a;
				mGates.push_back(std::move(g));
			}

			void move(Bit&& a, Bit& d)
			{
				//auto iter = mBitMap.find(&a);
				if (a.mAddress == ~0ull)
					throw std::runtime_error("uninitialized bit was moved. " LOCATION);

				if (d.mAddress != ~0ull)
					remove(d);

				//mBitMap[&d] = idx;
				//auto idx = a.mAddress;

				d.mCir = this;
				d.mAddress = a.mAddress;
				a.mAddress = ~0ull;
				//mBitMap.erase(iter);
			}

			void remove(Bit& a)
			{
				//auto iter = mBitMap.find(&a);
				if (a.mAddress == ~0ull)
					throw std::runtime_error("uninitialized bit was removed. " LOCATION);
				a.mAddress = ~0ull;
				//mBitMap.erase(iter);
			}

			Bit negate(const Bit& a)
			{
				Bit d;
				addBitMap(d);
				Gate g;
				g.mInput.push_back(getBitMap(a));
				g.mOutput.push_back(getBitMap(d));
				g.mType = OpType::na;
				mGates.push_back(std::move(g));
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
						u64 address = mInputs[i].mWires[j].address();
						vals[address] = in[i][j];
					}
				}

				for (u64 i = 0; i < mGates.size(); ++i)
				{
					auto& gate = mGates[i];
					switch (gate.mType)
					{
					case OpType::a:
						vals[gate.mOutput[0]] = vals[gate.mInput[0]];
						break;
					case OpType::na:
						vals[gate.mOutput[0]] = !vals[gate.mInput[0]];
						break;
					case OpType::And:
						vals[gate.mOutput[0]] = vals[gate.mInput[0]] & vals[gate.mInput[1]];
						break;
					case OpType::Or:
						vals[gate.mOutput[0]] = vals[gate.mInput[0]] | vals[gate.mInput[1]];
						break;
					case OpType::Xor:
						vals[gate.mOutput[0]] = vals[gate.mInput[0]] ^ vals[gate.mInput[1]];
						break;
					default:

						Print* p = dynamic_cast<Print*>(gate.mData.get());
						if (p)
						{
							BitVector v(gate.mInput.size());
							for (u64 j = 0; j < v.size(); ++j)
							{
								v[j] = vals[gate.mInput[j]];
							}
							std::cout << p->mFn(v);
						}
						else
						{
							throw std::runtime_error("MxCircuit::evaluate(...), gate type not implemented. " LOCATION);
						}
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

			oc::BetaCircuit asBetaCircuit() const;
			GraphCircuit asGraph() const;
		};


		template<typename T, typename = void>
		struct has_bit_representation_type : std::false_type
		{};

		template <typename T>
		struct has_bit_representation_type <T, std::void_t<
			// must have representation_type
			typename std::remove_reference_t<T>::representation_type,

			// must be Bit
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
			auto elems = t.serialize();
			o.addPrint(elems, t.toString());
			return o;
		}


		template<typename T>
		inline typename std::enable_if<
			has_bit_representation_type<T>::value == false
			, Circuit&>::type operator<<(Circuit& o, T&& t)
		{
			std::stringstream ss;
			ss << t;
			o.addPrint({}, [str = ss.str()](const BitVector&) ->std::string { return str; });
			return o;
		}

		template<typename T, typename ...Args>
		inline T Circuit::input(Args ... args)
		{

			mGates.reserve(1000);

			//Input in;
			T input(std::forward<Args>(args)...);
			auto elems = input.deserialize();
			IO in;
			in.mWires.reserve(elems.size());
			for (auto& e : elems)
			{
				//if (e->isConst())
				//	in.mWires.push_back(Wire{ e->constValue() });
				//else
				in.mWires.push_back(Wire{ addBitMap(*e) });
			}

			mInputs.reserve(10);
			mInputs.push_back(std::move(in));
			return input;
		}

		template<typename T>
		inline void Circuit::output(T& o)
		{
			//Input in;
			auto elems = o.serialize();
			IO out;
			out.mWires.reserve(elems.size());
			for (auto& e : elems)
			{
				if (e->isConst())
					out.mWires.push_back(Wire{ e->constValue() });
				else
					out.mWires.push_back(Wire{ getBitMap(*e) });
			}

			mOutputs.reserve(10);
			mOutputs.push_back(std::move(out));
		}


	}
}
#endif
