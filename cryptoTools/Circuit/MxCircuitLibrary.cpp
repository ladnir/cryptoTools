#include "MxCircuitLibrary.h"
#ifdef ENABLE_CIRCUITS

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

		// if twos complement, we have to sign extend. 
		// Otherwise we just return 0 if past the end.
		auto signExtend(span<const Bit> b, u64 i, IntType it) -> const Bit& {
			static const Bit zero = 0;
			if (it == IntType::TwosComplement)
				return b[std::min<u64>(i, b.size() - 1)];
			else if (i < b.size())
				return b[i];
			else
				return zero;
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


			BVector P(sSize), G(sSize - 1);
			Bit tempWire;
			//auto a1 = signExtendResize(a1_, sSize, it);
			//auto a2 = signExtendResize(a2_, sSize, it);;

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
						P[i] =
							signExtend(a1_, i, it) ^
							signExtend(a2_, i, it);
					}
					else
					{
						P[i] = !(
							signExtend(a1_, i, it) ^
							signExtend(a2_, i, it));
					}


					if (verbose)
						*cir << P[i];
				}

				if (i < sSize - 1)
				{
					if (at == AdderType::Addition)
					{
						G[i] =
							signExtend(a1_, i, it) &
							signExtend(a2_, i, it);
					}
					else
					{
						G[i] =
							(!signExtend(a1_, i, it)) &
							signExtend(a2_, i, it);
					}
				}
			}

			if (verbose)
			{
				*cir << "\nG ";
				for (u64 i = 0; i < sSize - 1; ++i)
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

						if (g.curWire.pos < sSize - 1)
						{
							auto& G1 = G[g.curWire.pos];
							G1 = G1 ^ (P1 & G0);
						}

						// propagate in is pointless since there is no global carry in.
						if (!g.first)
							P1 = P1 & P0;
					}
				}
			}

			P[0] = a1_[0] ^ a2_[0];
			sum[0] = P[0];
			for (u64 i = 1; i < sSize; ++i)
			{
				auto& a1i = signExtend(a1_, i, it);
				auto& a2i = signExtend(a2_, i, it);

				if (a1i.isConst() && a1i.constValue() == 0 && a2i.isConst() && a2i.constValue() == 0)
					P[i] = 0;
				else
					P[i] = a1i ^ a2i;

				sum[i] = P[i] ^ G[i - 1];
			}
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
					t[j] = t[2 * j + 0] & t[2 * j + 1];
				}
			}
			return t[0];
		}

		// ripple carry adder with parameters
		// a1, a2 and carry in cIn. The output is
		// 
		//    sum = a1[i] ^ a2[i] ^ cIn
		// and the carry out bit
		// 
		//    cOut
		// 
		// computed as
		//
		//  cIn ----*
		//              *--|----------------------*
		//              |  |                      |
		//              |  >= xor t1 -*           >= xor --- cOut
		//              |  |          |           |
		//  a1[i] ------*--*          >== and t3 -* 
		//              |             |
		//              >==== xor t2 -* 
		//              |  
		//  a2[i] ------*
		// 
		//   c  a1  a2 | t1 t2 t3 | c'
		//   0  0   0  | 0  0  0  | 0
		//   0  0   1  | 0  1  0  | 0
		//   0  1   0  | 1  1  1  | 0
		//   1  0   0  | 1  0  0  | 0
		//   0  1   1  | 1  0  0  | 1
		//   1  0   1  | 1  1  1  | 1
		//   1  1   0  | 0  1  0  | 1
		//   1  1   1  | 0  0  0  | 1
		//
		// The same algorithm can handle subtraction, i.e. a1-a2.
		// we have parameter a1,a2 and borrow in bIn.
		// 
		// sum is then a1 ^ a2 ^ bIn
		// borrow out bOut is computed as
		//
		//     bIn --------*
		//              *--|----------------------*
		//              |  |                      |
		//              |  >= xor t1 -*           >= xor --- bOut
		//              |  |          |           |
		//     a1 ------*--*          >== or t3 -* 
		//              |             |
		//              >==== xor t2 -* 
		//              |  
		//     a2 ------*
		// 
		//   b  a1  a2 | t1 t2 t3 | b'
		//   0  0   0  | 0  0  0  | 0
		//   0  0   1  | 0  1  1  | 1
		//   0  1   0  | 1  1  1  | 0
		//   1  0   0  | 1  0  1  | 1
		//   0  1   1  | 1  0  1  | 0
		//   1  0   1  | 1  1  1  | 1
		//   1  1   0  | 0  1  1  | 0
		//   1  1   1  | 0  0  0  | 1
		//
		// We unify these two as:
		// 
		//   cIn ----------*
		//              *--|----------------------*
		//              |  |                      |
		//              |  >= xor t1 -*           >= xor --- cOut
		//              |  |          |           |
		//  a1    ------*--*          >== G t3 -* 
		//              |             |
		//              >==== xor t2 -* 
		//              |  
		//  a2    ------*
		//
		//  a1 xor a2 xor cIn ---------------------- sum
		//
		// where G = addition ? and : or;
		void rippleAdder(
			Bit a1,
			Bit a2,
			Bit cIn,
			Bit& sum,
			Bit& cOut,
			AdderType at)
		{
			auto t1 = cIn ^ a1;
			auto t2 = a1 ^ a2;
			auto t3 = at == AdderType::Addition ?
				t1 & t2 :
				t1 | t2;
			sum = t2 ^ cIn;
			cOut = a1 ^ t3;
		}

		// a full ripple carry adder circuit. Has linear AND depth.
		// chains together single ripple adder units. works for addition
		// and subtraction.
		void rippleAdder(
			span<const Bit> a1,
			span<const Bit> a2,
			span<Bit> sum,
			IntType it,
			AdderType at)
		{
			Bit carry = 0;

			for (u64 i = 0; i < sum.size(); ++i)
			{
				if (i + 1 < sum.size())
				{
					// sum is assigned the sum. 
					// carry is pdated as the new carry bit.
					rippleAdder(
						signExtend(a1, i, it),
						signExtend(a2, i, it),
						carry, sum[i], carry, at);
				}
				else
				{
					// for the last one we dont need the carry out.
					sum[i] =
						signExtend(a1, i, it) ^
						signExtend(a2, i, it) ^
						carry;
				}
			}
		}

		// compute sum = x[0] + ... + x[n-1].
		// This is acheived in depth 
		//    log(n) + log(bitCount)         if op=depth
		// and 							     
		//    log(n) + bitCount              otherwise
		// 
		// the size will be 
		//    bitCount * (n + log(bitCount)  if op=depth
		// and
		//    bitCount * n                   otherwise
		//
		// the main idea is that given interger a,b,c
		// we can generate new intergers x,y  such that
		//
		//  a + b + c = x + y
		//
		// in a single round of interaction. This is done by
		// feeding a,b,c into parrallel ripple adders and letting
		// x be the summarion bits and y be the carry out bits.
		//
		// we can then build a tree of these until we have just 
		// two arguments left. We will then perform a normal addition.
		void parallelSummation(
			span<span<const Bit>> x,
			span<Bit> sum,
			Optimized op,
			IntType it
		)
		{
			auto verbose = false;
			auto& cir = *x[0][0].mCir;


			if (op == Optimized::Depth)
			{
				std::vector<BVector> temps; temps.reserve(x.size());
				for (auto i = 0ull; i < x.size(); ++i)
					temps.emplace_back(x[i].begin(), x[i].end());

				while (temps.size() > 2)
				{
					std::vector<BVector> t2; t2.reserve(temps.size() / 3 + 2);
					for (u64 i = 0; i < temps.size(); i += 3)
					{
						if (i + 3 <= temps.size())
						{
							t2.emplace_back();
							t2.emplace_back();
							auto& a = temps[i + 0];
							auto& b = temps[i + 1];
							auto& c = temps[i + 2];
							auto& x = *(t2.end() - 2);
							auto& y = *(t2.end() - 1);

							// for twos complement, there's an issue where
							//the result x,y are positive but wrap. In this
							// case if they have a small bit count, if we
							// later extend then, they will no longer wrap.
							// to fix this we just do all additions with the 
							// full bit length. unsigned does not have this issue.
							auto size =
								it == IntType::TwosComplement ?
								sum.size() :
								std::max<u64>({ a.size() + 1, b.size() + 1, c.size() });

							x.resize(size);
							y.resize(size);

							if (verbose)
							{

								BDynUInt A; A.mBits.insert(A.end(), a.begin(), a.end());
								BDynUInt B; B.mBits.insert(B.end(), b.begin(), b.end());
								BDynUInt C; C.mBits.insert(C.end(), c.begin(), c.end());
								cir << "\na " << A << " " << a << "\n";
								cir << "b " << B << " " << b << "\n";
								cir << "c " << C << " " << c << "\n";
							}

							for (u64 j = 0; j < size - 1; ++j)
								rippleAdder(
									signExtend(a, j, it),
									signExtend(b, j, it),
									signExtend(c, j, it),
									x[j], y[j + 1], AdderType::Addition);

							y[0] = 0;
							x[size - 1] =
								signExtend(a, size - 1, it) ^
								signExtend(b, size - 1, it) ^
								signExtend(c, size - 1, it);

							if (verbose)
							{

								BDynUInt X; X.mBits.insert(X.end(), x.begin(), x.end());
								BDynUInt Y; Y.mBits.insert(Y.end(), y.begin(), y.end());

								cir << "x " << X << " " << x << "\n";
								cir << "y " << Y << " " << y << "\n\n";

								BVector exp(size), act(size);
								rippleAdder(a, b, exp, it, AdderType::Addition);
								rippleAdder(c, exp, exp, it, AdderType::Addition);
								rippleAdder(x, y, act, it, AdderType::Addition);

								BDynUInt E; E.mBits.insert(E.end(), exp.begin(), exp.end());
								cir << "\nexp " << exp << " " << E << "\n";
								cir << "act " << act << "\n";
							}
						}
						else
						{
							while (i < temps.size())
							{
								if (verbose)
								{
									BDynUInt E; E.mBits.insert(E.end(), temps[i].begin(), temps[i].end());
									cir << "\nexp " << " " << E << "\n";
								}

								t2.emplace_back(temps[i++]);
							}
						}
					}
					if (verbose)
						cir << "--------------\n";

					temps = std::move(t2);
				}

				if (temps.size() == 2)
				{
					if (op == Optimized::Depth)
						parallelPrefix(temps[0], temps[1], sum, it, AdderType::Addition);
					else
						rippleAdder(temps[0], temps[1], sum, it, AdderType::Addition);
				}
				else
				{
					assert(temps.size() == 1);
					for (u64 i = 0; i < sum.size(); ++i)
						sum[i] = signExtend(temps[0], i, it);
				}

			}
			else
			{
				if (x.size() == 1)
				{
					for (u64 i = 0; i < sum.size(); ++i)
						sum[i] = signExtend(x[0], i, it);
				}
				else
				{
					rippleAdder(x[0], x[1], sum, it, AdderType::Addition);
					for (u64 i = 2; i < x.size(); ++i)
					{
						rippleAdder(sum, x[i], sum, it, AdderType::Addition);
					}
				}
			}
		}

		void multiply(
			span<const Bit> a,
			span<const Bit> b,
			span<Bit> c,
			Optimized op,
			IntType it)
		{
			// depth is improved if b is shorter.
			//if (b.size() > a.size())
			//	std::swap(b, a);

			// for twos complement, we need to sign extend b. Otherwise its just the min.
			u64 numRows = it == IntType::TwosComplement ? c.size() : std::min(b.size(), c.size());

			// rows will hold
			// {  (b[0] * a)  << 0,
			//    (b[1] * a)  << 1 ,
			//    (...     ) << ...,
			//    (b[n] * a) << n    }
			// where row i contains min(c.size() - i, a.size())
			std::vector<BVector> rows(numRows);
			std::vector<span<const Bit>> rowSpans(numRows);

			//auto& cir = *a[0].circuit();
			//cir << "\n";

			// first, we compute the AND between the two inputs.
			for (u64 i = 0; i < rows.size(); ++i)
			{
				// this will hold the b[i] * a
				rows[i].resize(std::min<u64>(c.size() - i, a.size()));

				// sign extend b if twos complement.
				const auto& bi = signExtend(b, i, it);

				// we will trim the most significant bits of  row[i] to the minimum.
				// This will be minimum of the size of c or (a * 2^i).
				rows[i].resize(std::min<u64>(c.size(), a.size() + i));

				// we will implicitly left shift using indicies.
				for (u64 j = i, k = 0; j < rows[i].size() && k < a.size(); ++j, ++k)
					rows[i][j] = bi & a[k];

				rowSpans[i] = rows[i].asBits();

				//BDynInt v; v.mBits.insert(v.mBits.end(), rows[i].begin(), rows[i].end());
				//cir << "row " << i << " " << v << "\t " << rows[i] << "\n";
			}

			// add up all the rows.
			parallelSummation(rowSpans, c, op, it);
		}



		void multiplex(
			Bit b,
			span<const Bit> bOne,
			span<const Bit> bZero,
			span<Bit> ret)
		{
			if (bZero.size() != ret.size() || bOne.size() != ret.size())
				throw RTE_LOC;

			for (u64 i = 0; i < ret.size(); ++i)
				ret[i] = bZero[i] ^ ((bZero[i] ^ bOne[i]) & b);
		}

		void negate(
			span<const Bit> a1,
			span<Bit> ret,
			Optimized op)
		{
			if (a1.size() != ret.size())
				throw RTE_LOC;
			Bit zero = 0;

			// ret = 0 - a1
			if (op == Optimized::Size)
				rippleAdder(span<const Bit>(&zero, 1), a1, ret,
					IntType::Unsigned, AdderType::Subtraction);
			else
				parallelPrefix(span<const Bit>(&zero, 1), a1, ret,
					IntType::Unsigned, AdderType::Subtraction);
		}

		void removeSign(
			span<const Bit> a1,
			span<Bit> ret,
			Optimized op)
		{

			Bit sign = a1.back();
			BVector t(a1.size());
			// ret = -a1
			negate(a1, t, op);

			// if(a1 < 0) ret = -a1
			// else       ret = a1
			multiplex(sign, t, a1, ret);
		}

		void addSign(
			Bit sign,
			span<const Bit> a1,
			span<Bit> ret,
			Optimized op)
		{
			// ret = -a1
			BVector t(a1.size());
			negate(a1, t, op);

			// if(sign) ret = -a1
			// else     ret = a1
			multiplex(sign, t, a1, ret);
		}

		// 
		void lessThan(
			span<const Bit> a1,
			span<const Bit> a2,
			Bit& ret,
			IntType it,
			Optimized op)
		{
			BVector temp(std::max<u64>(a1.size(), a2.size()) + 1);
			if (op == Optimized::Size)
				rippleAdder(a1, a2, temp, it, AdderType::Subtraction);
			else
				parallelPrefix(a1, a2, temp, it, AdderType::Subtraction);

			ret = temp.back();
		}

		// we are computing dividend / divider = quot  with optional remainder rem
		void divideRemainder(
			span<const Bit> dividend,
			span<const Bit> divider,
			span<Bit> quotient,
			span<Bit> rem,
			Optimized op,
			IntType it)
		{
			bool verbose = false;
			auto& cir = *dividend[0].mCir;
			auto asInt = [](auto&& v) {
				BDynUInt d;
				d.mBits.insert(d.mBits.begin(), v.begin(), v.end());
				return d;
				};

			if (quotient.size() != dividend.size())
				throw std::runtime_error(LOCATION);

			if (it == IntType::TwosComplement)
			{
				// remove the sign and then call the unsigned version. Then
				// add the sign back.

				Bit dividendSign = dividend.back(),
					dividerSign = divider.back(),
					sign = dividendSign ^ dividerSign;

				if (verbose)
				{
					cir << "q sign " << sign << " = " << dividendSign << " / " << dividerSign << "\n";
				}

				BVector
					unsgineddividend(dividend.size()),
					unsigneddivider(divider.size());

				removeSign(dividend, unsgineddividend, op);
				removeSign(divider, unsigneddivider, op);
				BVector remainder(rem.size());

				divideRemainder(
					unsgineddividend, unsigneddivider,
					quotient, remainder,
					op, IntType::Unsigned);

				addSign(sign, quotient, quotient, op);

				if (rem.size())
				{
					// we follow the cpp notion of signed mod.
					addSign(dividendSign, remainder, rem, op);
				}
			}
			else
			{
				// We will shift the dividend up until its lsb is aligned 
				// with the msb if the divider. We will then check if we 
				// can subtract the shifted dividend. If so we subtract it
				// and mark the quotient bit as 1.
				// 
				// We then shift the divider back down one position and
				// repeat, where we now compare with the current value.
				// 
				// exmaple:
				//         001110
				//        ----------------
				//   011 |   101101
				//         011                  \. 
				//       - 000             0    |
				//         --------             | 
				//           101101             | 
				//          011                 | 
				//        - 000            0    | q
				//          -------             | u
				//           101101             | o
				//           011                | t
				//         - 011            1   | i
				//           ------             | e
				//            10101             | n
				//            011               | t
				//          - 011           1   | 
				//            -----             | 
				//             1001             | 
				//             011              | 
				//           - 011          1   |
				//            -----             | 
				//              001             | 
				//              011             | 
				//           -  000         0   |
				//             ----             / 
				//              001        <==== remainder
				//

				// current =  dividend
				BVector current; current.insert(current.begin(), dividend.begin(), dividend.end());

				u64 shifts = quotient.size() - 1;

				if (verbose)
				{
					cir << "computing " << asInt(dividend) << " / " << asInt(divider) << "\n";
				}
				for (i64 i = shifts; i >= 0; --i)
				{
					// extract the relavent part of current. This is the part that 
					//lines up with the current shift of divider.
					auto cBegin = current.begin() + i;
					auto cEnd = current.begin() + std::min<u64>(i + divider.size() + 1, current.size());
					span<Bit> c2(cBegin, cEnd);

					if (verbose)
					{
						BVector div(i); div.insert(div.end(), divider.begin(), divider.end());
						cir << "-------- " << i << "\n";
						cir << "cur  " << current << " " << asInt(current) << "\n";
						cir << "div  " << div << " " << asInt(div) << "\n";
						cir << "C    " << std::string(i, ' ') << c2 << " " << asInt(c2) << "\n";
						cir << "D    " << std::string(i, ' ') << divider << " " << asInt(divider) << "\n";
					}

					// quotient[i] = (c2 >= divider)
					//             = !(c2 < divider)
					lessThan(c2, divider, quotient[i], IntType::Unsigned, op);
					quotient[i] = !quotient[i];

					if (verbose)
					{
						cir << "Q[" << i << "] = " << quotient[i] << " = " << asInt(c2) << " >= " << asInt(divider) << "\n";
					}

					// sub will b zero if quotient[i] is zero. Otherwise
					// its the (logically shifted) divider.
					BVector sub(std::min<u64>(c2.size(), divider.size()));
					for (u64 j = 0; j < sub.size(); ++j)
						sub[j] = divider[j] & quotient[i];


					if (verbose)
					{
						BVector S(i); S.insert(S.end(), sub.begin(), sub.end());
						cir << "sub  " << S << " " << asInt(S) << "\n";
					}
					// subtract sub. The relvent bits of current will be updated.
					if (op == Optimized::Size)
						rippleAdder(c2, sub, c2, IntType::Unsigned, AdderType::Subtraction);
					else
						parallelPrefix(c2, sub, c2, IntType::Unsigned, AdderType::Subtraction);


					if (verbose)
					{
						cir << "cur* " << current << "\n";
					}
				}

				for (u64 i = 0; i < std::min<u64>(current.size(), rem.size()); ++i)
					rem[i] = current[i];
				for (u64 i = current.size(); i < rem.size(); ++i)
					rem[i] = 0;
			}
		}
	}
}
#endif
