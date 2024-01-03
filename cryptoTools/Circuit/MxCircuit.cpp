#include "MxCircuit.h"
#ifdef ENABLE_CIRCUITS

#include "MxTypes.h"
#include "MxCircuitLibrary.h"
#include <unordered_set>

namespace osuCrypto
{
	namespace Mx
	{

		Circuit& operator<<(Circuit& o, span<const Bit> bits)
		{
			std::vector<const Bit*> b(bits.size());
			for (u64 i = 0; i < b.size(); ++i)
				b[i] = &bits[i];
			o.addPrint(b, BVector::toString());
			return o;
		}

		struct Mapper
		{
			std::vector<u64> mMap;

			void map(u64 key, u64 val) {
				if (mMap.size() <= key)
					mMap.resize(std::max<u64>(key + 1, mMap.size() * 2), ~0ull);
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

		BetaCircuit Circuit::asBetaCircuit()
		{
			auto childEdges = computeChildEdges();

			BetaCircuit cir;
			Mapper addressMap;
			std::vector<u64> depCount(mGates.size());
			std::vector<u64>
				linearQueue,
				NonlinearQueue, non;
			linearQueue.reserve(1024);
			NonlinearQueue.reserve(256);
			non.reserve(256);

			for (u64 i = 0; i < mGates.size(); ++i)
			{
				depCount[i] = mGates[i].mInput.size();
				if (depCount[i] == 0)
				{
					linearQueue.push_back(i);
				}
			}

			for (u64 i = 0; i < mInputs.size(); ++i)
			{
				auto& in = mGates[mInputs[i]];

				BetaBundle b(in.mNumOutputs);
				cir.addInputBundle(b);
				addressMap.map(mInputs[i], b[0]);
			}

			std::vector<BetaBundle> outputs(mOutputs.size());
			for (u64 i = 0; i < mOutputs.size(); ++i)
			{
				auto& out = mGates[mOutputs[i]];

				outputs[i].resize(out.mInput.size());
				cir.addOutputBundle(outputs[i]);
				//addressMap.map(mOutputs[i], b[0]);
			}

			DirtyFlag dirty;

			auto evalNode = [&](u64 idx) {
				auto& node = mGates[idx];

				// if not an output (which has already been mapped).
				if (addressMap.hasMapping(idx) == false)
				{
					if (node.mNumOutputs)
					{
						BetaWire next;
						cir.addTempWire(next);
						addressMap.map(idx, next);
						for (u64 i = 1; i < node.mNumOutputs; ++i)
							cir.addTempWire(next);
					}
				}

				for (auto i : node.mInput)
					if (dirty.find(i.gate()) != dirty.end())
						throw RTE_LOC;
				if (addressMap.hasMapping(idx))
				{
					auto outIdx = addressMap[idx];
					if (outIdx == 131)
						std::cout << "here" << std::endl;
				}
				switch (node.mType)
				{
				case OpType::a:
					cir.addCopy(
						addressMap[node.mInput[0].gate()] + node.mInput[0].offset(),
						addressMap[idx]);

					++cir.mLevelCounts.back();
					break;
				case OpType::na:
					cir.addInvert(
						addressMap[node.mInput[0].gate()] + node.mInput[0].offset(),
						addressMap[idx]);

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
				{
					auto g0 = node.mInput[0].gate();
					auto o0 = node.mInput[0].offset();
					auto g1 = node.mInput[1].gate();
					auto o1 = node.mInput[1].offset();

					cir.addGate(
						addressMap[g0] + o0,
						addressMap[g1] + o1,
						(oc::GateType)node.mType,
						addressMap[idx]);

					++cir.mLevelCounts.back();
					if (isLinear(node.mType) == false)
					{
						++cir.mLevelAndCounts.back();
						dirty.insert(idx);
					}

					break;
				}
				case OpType::Print:
				{

					auto s = node.mInput.size();
					if (s && node.mInput.back().offset() == ~0ull)
						--s;

					BetaBundle b(s);
					for (u64 i = 0; i < b.size(); ++i)
						b[i] = addressMap[node.mInput[i].gate()] + node.mInput[i].offset();
					cir.addPrint(b, static_cast<Print*>(node.mData.get())->mFn);

					break;
				}
				case OpType::Input:
					if (addressMap.hasMapping(idx) == false)
						throw RTE_LOC;
					break;
				case OpType::Output:

					for (u64 i = 0; i < node.mInput.size(); ++i)
						if (addressMap.hasMapping(node.mInput[i].gate()) == false)
							throw RTE_LOC;
					break;
				default:
					throw RTE_LOC;
					break;
				}
				auto& children = childEdges.mChildren[idx];

				for (auto b = children.begin(); b != children.end(); ++b) {
					auto c = b->gate();
					if (depCount[c] == 0)
						throw RTE_LOC;
					--depCount[c];

					if (depCount[c] == 0)
					{
						if (mGates[c].isLinear())
							linearQueue.push_back(c);
						else
							NonlinearQueue.push_back(c);
					}
				}
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

			if (cir.mLevelAndCounts.size() == 0 || cir.mLevelAndCounts.back())
			{
				cir.mLevelCounts.emplace_back();
				cir.mLevelAndCounts.emplace_back();
			}
			for (u64 i = 0; i < mOutputs.size(); ++i)
			{
				auto& out = mGates[mOutputs[i]];
				for (u64 j = 0; j < out.mInput.size(); ++j)
				{
					auto s = addressMap[out.mInput[j].gate()] + out.mInput[j].offset();
					auto d = outputs[i][j];
					cir.addCopy(s, d);
					++cir.mLevelCounts.back();
				}
			}

			for (u64 i = 0; i < depCount.size(); ++i)
			{
				if (depCount[i])
					throw RTE_LOC;
			}

			return cir;
		}


		auto Circuit::computeChildEdges() -> ChildEdges
		{

			ChildEdges r;
			std::vector<u64> depCount(mGates.size());
			u64 total = 0;

			// count how many things depend on each gate.
			for (u64 i = 0; i < mGates.size(); ++i)
			{
				for (auto j : mGates[i].mInput)
				{
					++depCount[j.gate()];
				}
				total += mGates[i].mInput.size();
			}

			r.mChildArena.reserve(total);
			r.mChildren.resize(mGates.size());

			// allocate buffers for each.
			for (u64 i = 0; i < mGates.size(); ++i)
			{
				r.mChildren[i] = r.mChildArena.allocate(depCount[i]);
				depCount[i] = 0;
			}

			//populate the children pointers
			for (u64 i = 0; i < mGates.size(); ++i)
			{
				for (auto j : mGates[i].mInput)
				{
					auto& dc = depCount[j.gate()];
					r.mChildren[j.gate()][dc] = Address(i, j.offset());
					++dc;
				}
			}
			return r;
		}

		//GraphCircuit Circuit::asGraph() 
		//{

		//	GraphCircuit ret;
		//	using Node = GraphCircuit::Node;
		//	using InputNode = GraphCircuit::InputNode;
		//	using OpNode = GraphCircuit::OpNode;
		//	using OutputNode = GraphCircuit::OutputNode;
		//	using PrintNode = GraphCircuit::PrintNode;


		//	//u64 nextAddress = 0;
		//	//Mapper addressMap, owner;

		//	ret.mNodes.reserve(mGates.size() + mInputs.size() + mOutputs.size() + 1);
		//	ret.mNodes.emplace_back();
		//	
		//	u64 prePrint = 0;

		//	//for (u64 i = 0; i < mInputs.size(); ++i)
		//	//{

		//	//}




		//	{
		//		Node n;
		//		switch (mGates[i].mType)
		//		{
		//		case OpType::Input:
		//		{
		//			auto idx = ret.mNodes.size();
		//			Node n;
		//			n.addDep(0);
		//			ret.mNodes.front().addChild(idx);

		//			n.mData = InputNode{ i };
		//			for (u64 j = 0; j < mInputs[i].mWires.size(); ++j)
		//			{
		//				auto oldAddress = mInputs[i].mWires[j].address();
		//				auto address = nextAddress++;
		//				owner.map(address, idx);
		//				addressMap.map(oldAddress, address);
		//				n.mOutputs.push_back(address);
		//			}
		//			ret.mInputs.push_back(idx);
		//			ret.mNodes.push_back(std::move(n));
		//			break;
		//		}
		//		case OpType::Print:
		//		{
		//			auto p = dynamic_cast<Print*>(mGates[i].mData.get());
		//			if (p)
		//			{
		//				n.mData = PrintNode{ &p->mFn };
		//				for (u64 j = 0; j < mGates[i].mInput.size(); ++j)
		//				{
		//					auto address = addressMap[mGates[i].mInput[j]];
		//					n.mInputs.push_back(address);
		//					n.addDep(owner[address]);

		//					auto& p = ret.mNodes[owner[address]];
		//					p.addChild(ret.mNodes.size());
		//				}

		//				n.addDep(prePrint);
		//				auto& p = ret.mNodes[prePrint];
		//				p.addChild(ret.mNodes.size());
		//				prePrint = ret.mNodes.size();
		//			}
		//			else
		//			{
		//				throw RTE_LOC;
		//			}
		//			break;
		//		}
		//		default:
		//			if ((int)mGates[i].mType > (int)OpType::One)
		//				throw RTE_LOC;

		//			n.mData = OpNode{ mGates[i].mType };

		//			for (u64 j = 0; j < mGates[i].mInput.size(); ++j)
		//			{
		//				auto address = addressMap[mGates[i].mInput[j]];
		//				n.mInputs.push_back(address);
		//				n.addDep(owner[address]);
		//				auto& p = ret.mNodes[owner[address]];
		//				p.addChild(ret.mNodes.size());
		//				if (address == -1)
		//					throw RTE_LOC;;
		//			}
		//			for (u64 j = 0; j < mGates[i].mOutput.size(); ++j)
		//			{
		//				auto address = nextAddress++;
		//				owner.map(address, ret.mNodes.size());
		//				addressMap.map(mGates[i].mOutput[j], address);
		//				n.mOutputs.push_back(address);
		//			}
		//			break;
		//		}
		//		ret.mNodes.push_back(std::move(n));
		//	}

		//	for (u64 i = 0; i < mOutputs.size(); ++i)
		//	{
		//		Node n;
		//		n.mData = OutputNode{ i };
		//		for (u64 j = 0; j < mOutputs[i].mWires.size(); ++j)
		//		{
		//			auto address = addressMap[mOutputs[i].mWires[j].address()];
		//			n.mInputs.push_back(address);
		//			n.addDep(owner[address]);
		//			auto& p = ret.mNodes[owner[address]];
		//			p.addChild(ret.mNodes.size());
		//		}

		//		ret.mOutputs.push_back(ret.mNodes.size());
		//		ret.mNodes.push_back(std::move(n));
		//	}
		//	return ret;
		//}
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
