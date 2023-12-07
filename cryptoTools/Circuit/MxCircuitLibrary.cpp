#include "MxCircuitLibrary.h"
#include "MxTypes.h"
#include "MxCircuit.h"
namespace osuCrypto
{
	namespace Mx
	{

		Circuit* findCircuit(span<const Bit> v)
		{
			for (auto& vv : v)
				if (vv.isConst() == false)
					return vv.mCir;
			return nullptr;
		}

		void parallelPrefix(span<const Bit> a1_, span<const Bit> a2_, span<Bit> sum, IntType it, AdderType at)
		{
			u64 sSize = sum.size();
			bool verbose = false;
			Circuit* cir;
			if (verbose)
			{
				cir = findCircuit(a1_);
				cir = cir ? cir : findCircuit(a2_);
				if (!cir)
					throw RTE_LOC;

				*cir << "\na ";
				for (auto& aa : a1_)
					*cir << aa;
				*cir << "\nb ";
				for (auto& aa : a2_)
					*cir << aa;
				*cir << "\n";

			}

			// This is a Parallel Prefix Adder where we use generate & propagate
			// The main idea is that for each bit position, we first compute two
			// bits, propagate P[i] and generate G[i]. P[i] denote that at bit
			// position i, if there is a "carry-in", then this position will propagate
			// the carry to position i+1. G[i] denotes that position i will always
			// result in a carry.  The sum is then S[i] = P[i] ^ G[i-1]. Importantly,
			// the P[i], G[i] bits can be computed in a tree structure. First observe
			// that a region of bits [i,i-1,...,j+1,j] = [i:j] themselves can generate
			// a pair P[*], G[*]. This will denote whether that region as a block will
			// propagate or generate out the most significant position.
			// We can therefore compute:
			//
			//  P[i] = P[0:i] = P[j:i] & P[0:j-1].
			//  G[i] = G[0:i] = G[j:i] or (G[0:j-1] & P[j:i])
			//                = G[j:i] ^  (G[0:j-1] & P[j:i])
			//
			// Note that this holds for all regions, not just [0:i]. We then compute a
			// binary tree of these bits. For the first level of the tree (leaves)
			// we compute:
			//
			//  P[i:i] = A[i] ^ B[i]
			//  G[i:i] = A[i] & B[i]
			//
			// For subtraction, its basically the same but we have:
			// 
			//  P[i:i] = !(A[i] ^ B[i])
			//  G[i:i] = !A[i] & B[i]
			// 
			// Also see: Harris, D. A taxonomy of parallel prefix networks. In IEEE ASILOMAR (2003).


			BVector P(sSize), G(sSize-1);
			Bit tempWire;
			auto a1 = signExtendResize(a1_, sSize, it);
			auto a2 = signExtendResize(a2_, sSize, it);;

			if (verbose)
				*cir << "P ";
			for (u64 i = 0; i < sSize; ++i)
			{

				//if (a1[i] == 0 && a2[i] == 0)
				//	P[i] = 0;
				//else
				{
					if (at == AdderType::Addition)
					{
						P[i] = a1[i] ^ a2[i];
					}
					else
					{
						P[i] = !(a1[i] ^ a2[i]);
					}


					if (verbose)
						*cir <<  P[i];
				}

				if (i < sSize - 1)
				{
					if (at == AdderType::Addition)
						G[i] = a1[i] & a2[i];
					else
						G[i] = (!a1[i]) & a2[i];
				}
			}

			if (verbose)
			{
				*cir << "\nG ";
				for (u64 i = 0; i < sSize-1; ++i)
					*cir << G[i];
				*cir << "\n";
			}

			// Sklansky algorithm
			auto d = log2ceil(sSize);

			struct Idx { u64 lvl = (u64)-1, pos = (u64)-1; };
			struct Node
			{
				bool first, used = false, enqued = false;
				Idx curWire, lowWire;
			};
			Matrix<Node> graph(d, sSize);

			std::vector<u64> lvls(sSize, -1);
			for (u64 level = 0; level < d; ++level)
			{
				// 1,2,4,8,16,32,64,...
				auto startPos = 1ull << level;
				auto step = 1 << (level + 1);

				bool first = true;
				for (u64 i = startPos; i < sSize; i += step)
				{
					auto lowWire = i - 1;

					auto endPos = std::min<u64>(i + startPos, sSize);
					for (auto curWire = i; curWire < endPos; ++curWire)
					{
						graph(level, curWire).curWire = { lvls[curWire], curWire };
						graph(level, curWire).lowWire = { lvls[lowWire], lowWire };
						graph(level, curWire).first = first;
						lvls[curWire] = level;
					}
					first = false;
				}
			}

			std::vector<Idx> stack;
			auto add = [&](Idx idx)
				{
					assert(idx.pos != (u64)-1);

					if (idx.lvl != (u64)-1)
					{
						auto& c0 = graph(idx.lvl, idx.pos);
						if (c0.enqued == false)
						{
							assert(c0.used == false);
							c0.enqued = true;
							stack.push_back(idx);
						}
					}
				};

			for (u64 i = 1; i < sSize; ++i)
			{
				add({ lvls[i - 1],i - 1 });
			}
			for (u64 i = 0; i < stack.size(); ++i)
			{
				auto lvl = stack[i].lvl;
				auto pos = stack[i].pos;
				auto& g = graph(lvl, pos);
				g.used = true;

				if (lvl) {
					add(g.curWire);
					add(g.lowWire);
				}
			}

			for (u64 level = 0; level < d; ++level)
			{
				for (u64 i = 0; i < sSize; ++i)
				{

					auto& g = graph(level, i);
					if (g.used)
					{

						auto& P0 = P[g.lowWire.pos];
						auto& G0 = G[g.lowWire.pos];
						auto& P1 = P[g.curWire.pos];

						//std::cout << "G " << g.curWire.pos << " " << g.lowWire.pos << " " << int(g.first) << std::endl;

						if (g.curWire.pos < sSize - 1)
						{
							auto& G1 = G[g.curWire.pos];


							// G1 = G1 ^ P1 & G0
							G1 = G1 ^ (P1 & G0);

							//cd.addGate(P1, G0, GateType::And, tempWire);
							//cd.addGate(tempWire, G1, GateType::Xor, G1);
							//cd << "G " << g.curWire.pos << " " << g.lowWire.pos << " " << int(g.first) << " ~  " << G1 << "\n";

						}

						// propagate in is pointless since there is no global carry in.
						if (!g.first) {
							// P1 = P1 & P0
							P1 = P1 & P0;
							//cd.addGate(P0, P1, GateType::And, P1);
							//cd << "P " << g.curWire.pos << " " << g.lowWire.pos << " " << int(g.first) << " ~  " << P1 << "\n";

						}


					}
				}
			}

			P[0] = a1[0] ^ a2[0];
			sum[0] = P[0];
			//cd.addGate(a1.mWires[0], a2.mWires[0], GateType::Xor, P[0]);
			for (u64 i = 1; i < sSize; ++i)
			{
				//if (sum[i] != (BetaWire)-1)
				{
					// s[i] = P[i] ^ G[i-1]
					if (a1[i] == 0 && a2[i] == 0)
						P[i] = 0;
					//cd.addConst(P[i], 0);
					else
						P[i] = a1[i] ^ a2[i];
					//cd.addGate(a1.mWires[i], a2.mWires[i], GateType::Xor, P[i]);

					//cd.addGate(P[i], G[i - 1], GateType::Xor, sum.mWires[i]);
					sum[i] = P[i] ^ G[i - 1];
				}
			}

			//std::cout << "~~~~~~~~~~~\n";	
			//cd << "**~~~~~~~~~~~\n";
		}


		Bit parallelEquality(span<const Bit> a1, span<const Bit> a2)
		{
			auto bits = a1.size();
			if (a2.size() != bits)
				throw RTE_LOC;

			BVector t(bits);
			for (u64 i = 0; i < bits; ++i)
				t[i] = ~(a1[i] ^ a2[i]);

			auto levels = log2ceil(bits);
			for (u64 i = 0; i < levels; ++i)
			{
				auto step = 1ull << i;
				auto size = bits / 2 / step;
				for (u64 j = 0; j < size; ++j)
				{
					t[j] =  t[2 * j + 0] & t[2 * j + 1];
				}
			}
			return t[0];
		}

	}
}