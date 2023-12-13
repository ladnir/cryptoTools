#include "MxCircuit.h"
#ifdef ENABLE_CIRCUITS

#include "MxTypes.h"
#include "MxCircuitLibrary.h"
#include <unordered_set>

namespace osuCrypto
{
	namespace Mx
	{

		struct Mapper
		{
			std::vector<u64> mMap;

			void map(u64 key, u64 val) {
				if (mMap.size() <= key)
					mMap.resize(std::max<u64>(key + 1, mMap.size() * 2), -1);
				mMap[key] = val;
			};

			u64 operator[](u64 key)
			{
				if (hasMapping(key) == false)
					throw RTE_LOC;
				return mMap[key];
			}

			bool hasMapping(u64 key)
			{
				return mMap.size() > key && mMap[key] != ~0ull;
			}
		};

		struct DirtyFlag
		{
			std::vector<u8> dirty;

			auto end() { return dirty.end(); }
			auto find(u64 i)
			{
				if (i >= dirty.size() || dirty[i] == 0)
					return end();
				return dirty.begin() + i;
			}

			void insert(u64 i)
			{
				if (dirty.size() <= i)
				{
					auto ns = std::max<u64>({ dirty.size() * 2, i + 1, 16 });
					dirty.resize(ns);
				}
				dirty[i] = 1;
			}

			void clear()
			{
				memset(dirty.data(), 0, dirty.size());
			}
		};

		BetaCircuit Circuit::asBetaCircuit() const
		{
			auto g = asGraph();


			BetaCircuit cir;
			Mapper addressMap;
			for (u64 i = 0; i < g.mInputs.size(); ++i)
			{
				auto& in = g.mNodes[g.mInputs[i]];

				in.mData | match{
					[](GraphCircuit::InputNode&) {},
					[](auto&&) {throw RTE_LOC; }
				};
				BetaBundle b(in.mOutputs.size());
				cir.addInputBundle(b);
				for (u64 j = 0; j < in.mOutputs.size(); ++j)
				{
					auto address = b[j];
					addressMap.map(in.mOutputs[j], address);
				}
			}

			for (u64 i = 0; i < g.mOutputs.size(); ++i)
			{
				auto& out = g.mNodes[g.mOutputs[i]];

				BetaBundle b(out.mInputs.size());
				cir.addOutputBundle(b);
				for (u64 j = 0; j < out.mInputs.size(); ++j)
				{
					auto address = b[j];
					addressMap.map(out.mInputs[j], address);
				}
			}

			std::vector<u64>
				linearQueue{ 0 },
				NonlinearQueue, non;
			DirtyFlag dirty;


			auto evalNode = [&](u64 idx) {
				auto& node = g.mNodes[idx];

				for (u64 i = 0; i < node.mOutputs.size(); ++i)
				{
					auto o = node.mOutputs[i];
					if (addressMap.hasMapping(o) == false)
					{
						BetaWire next;
						cir.addTempWire(next);
						addressMap.map(o, next);
					}
				}

				for (auto i : node.mInputs)
					if (dirty.find(i) != dirty.end())
						throw RTE_LOC;

				node.mData | match{
					[&](GraphCircuit::OpNode& o) {
						switch (o.mType)
						{
						case OpType::a:
							cir.addCopy(
								addressMap[node.mInputs[0]],
								addressMap[node.mOutputs[0]]);

							++cir.mLevelCounts.back();
							break;
						case OpType::na:
							cir.addInvert(
								addressMap[node.mInputs[0]],
								addressMap[node.mOutputs[0]]);

							++cir.mLevelCounts.back();
							break;
						case OpType::And:
						case OpType::Or:
						case OpType::Xor:
						case OpType::Nand:
						case OpType::na_And:
						case OpType::na_Or:
						case OpType::nb_And:
						case OpType::nb_Or:
						case OpType::Nor:
						case OpType::Nxor:
							cir.addGate(
								addressMap[node.mInputs[0]],
								addressMap[node.mInputs[1]],
								(oc::GateType)o.mType,
								addressMap[node.mOutputs[0]]);

							++cir.mLevelCounts.back();
							if (isLinear(o.mType) == false)
							{
								++cir.mLevelAndCounts.back();
								dirty.insert(node.mOutputs[0]);
							}

							break;
							default:
								throw RTE_LOC;
						break;
						}
					},
					[&](GraphCircuit::PrintNode& p) {
						BetaBundle b(node.mInputs.size());
						for (u64 i = 0; i < b.size(); ++i)
							b[i] = addressMap[node.mInputs[i]];
						cir.addPrint(b, *p.mFn);
					},
					[&](GraphCircuit::OutputNode& o) {

						for (u64 i = 0; i < node.mInputs.size(); ++i)
							if (addressMap.hasMapping(node.mInputs[i]) == false)
								throw RTE_LOC;
					},
					[&](GraphCircuit::InputNode& o) {

						for (u64 i = 0; i < node.mInputs.size(); ++i)
							if (addressMap.hasMapping(node.mInputs[i]) == false)
								throw RTE_LOC;
					}
				};
;

				
				node.mChildren.forEach([&](u64 c) {

					g.mNodes[c].removeDep(idx);

					if (g.mNodes[c].mDeps.size() == 0)
					{
						if (g.mNodes[c].isLinear())
							linearQueue.push_back(c);
						else
							NonlinearQueue.push_back(c);
					}
				});
			};

			while (linearQueue.size() || NonlinearQueue.size())
			{
				dirty.clear();

				cir.mLevelCounts.emplace_back();
				cir.mLevelAndCounts.emplace_back();
				while (linearQueue.size())
				{
					auto idx = linearQueue.back();
					linearQueue.pop_back();
					evalNode(idx);
				}
				std::swap(non, NonlinearQueue);
				//auto n = std::move(NonlinearQueue);

				while (non.size())
				{
					auto idx = non.back();
					non.pop_back();
					evalNode(idx);
				}
			}

			for (u64 i = 0; i < g.mNodes.size(); ++i)
			{
				if (g.mNodes[i].mDeps.size())
					throw RTE_LOC;
			}

			return cir;
		}


		GraphCircuit Circuit::asGraph() const
		{

			GraphCircuit ret;
			using Node = GraphCircuit::Node;
			using InputNode = GraphCircuit::InputNode;
			using OpNode = GraphCircuit::OpNode;
			using OutputNode = GraphCircuit::OutputNode;
			using PrintNode = GraphCircuit::PrintNode;


			u64 nextAddress = 0;
			Mapper addressMap, owner;

			ret.mNodes.reserve(mGates.size() + mInputs.size() + mOutputs.size() + 1);
			ret.mNodes.emplace_back();
			
			u64 prePrint = 0;

			for (u64 i = 0; i < mInputs.size(); ++i)
			{
				auto idx = ret.mNodes.size();
				Node n;
				n.addDep(0);
				ret.mNodes.front().addChild(idx);

				n.mData = InputNode{ i };
				for (u64 j = 0; j < mInputs[i].mWires.size(); ++j)
				{
					auto oldAddress = mInputs[i].mWires[j].address();
					auto address = nextAddress++;
					owner.map(address, idx);
					addressMap.map(oldAddress, address);
					n.mOutputs.push_back(address);
				}
				ret.mInputs.push_back(idx);
				ret.mNodes.push_back(std::move(n));
			}


			for (u64 i = 0; i < mGates.size(); ++i)
			{
				Node n;
				switch (mGates[i].mType)
				{
				case OpType::Other:
				{
					auto p = dynamic_cast<Print*>(mGates[i].mData.get());
					if (p)
					{
						n.mData = PrintNode{ &p->mFn };
						for (u64 j = 0; j < mGates[i].mInput.size(); ++j)
						{
							auto address = addressMap[mGates[i].mInput[j]];
							n.mInputs.push_back(address);
							n.addDep(owner[address]);

							auto& p = ret.mNodes[owner[address]];
							p.addChild(ret.mNodes.size());
						}

						n.addDep(prePrint);
						auto& p = ret.mNodes[prePrint];
						p.addChild(ret.mNodes.size());
						prePrint = ret.mNodes.size();
					}
					else
					{
						throw RTE_LOC;
					}
					break;
				}
				default:
					if ((int)mGates[i].mType > (int)OpType::One)
						throw RTE_LOC;

					n.mData = OpNode{ mGates[i].mType };

					for (u64 j = 0; j < mGates[i].mInput.size(); ++j)
					{
						auto address = addressMap[mGates[i].mInput[j]];
						n.mInputs.push_back(address);
						n.addDep(owner[address]);
						auto& p = ret.mNodes[owner[address]];
						p.addChild(ret.mNodes.size());
						if (address == -1)
							throw RTE_LOC;;
					}
					for (u64 j = 0; j < mGates[i].mOutput.size(); ++j)
					{
						auto address = nextAddress++;
						owner.map(address, ret.mNodes.size());
						addressMap.map(mGates[i].mOutput[j], address);
						n.mOutputs.push_back(address);
					}
					break;
				}
				ret.mNodes.push_back(std::move(n));
			}

			for (u64 i = 0; i < mOutputs.size(); ++i)
			{
				Node n;
				n.mData = OutputNode{ i };
				for (u64 j = 0; j < mOutputs[i].mWires.size(); ++j)
				{
					auto address = addressMap[mOutputs[i].mWires[j].address()];
					n.mInputs.push_back(address);
					n.addDep(owner[address]);
					auto& p = ret.mNodes[owner[address]];
					p.addChild(ret.mNodes.size());
				}

				ret.mOutputs.push_back(ret.mNodes.size());
				ret.mNodes.push_back(std::move(n));
			}
			return ret;
		}
		//struct VBit
		//{

		//};

		//template<typename F0, typename F1>
		////void If(Bit, F0, F1);

		//void foo()
		//{
		//	Circuit cir;
		//	auto b = cir.input<Bit>();

		//	auto a = cir.input<BitArray<128>>();

		//	auto c = BInt<32>(4);
		//	auto d = cir.input<BInt>();

		//	b = b ^ b;

		//	a = a ^ a;

		//	c = c + c;

		//	auto bv = cir.input<BitVector>(128);

		//	b.select(a, d);

		//	cir << "c + c = " << c << "\val";

		//	cir.output(c);
		//}

	}
}
#endif
