#include "MxCircuit_Tests.h"
#include "cryptoTools/Circuit/MxCircuit.h"
#include "cryptoTools/Circuit/MxCircuitLibrary.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Circuit/MxTypes.h"
#include "cryptoTools/Circuit/Mx2.h"

using namespace oc;
i64 signExtend(i64 v, u64 b, bool print = false);

void MxCircuit_Bit_Ops_Test(const oc::CLP& cmd)
{
	bool verbose = cmd.isSet("verbose");
	Mx::Circuit cir;

	{
		auto a = cir.input<Mx::Bit>();
		auto b = cir.input<Mx::Bit>();
		auto c = Mx::Bit(1);

		auto vAnd = a & b;
		auto vOr = a | b;
		auto vXor = a ^ b;
		auto vNot = !a;
		auto zAnd = a & c;
		auto zOr = a | c;
		auto zXor = a ^ c;

		if (verbose)
		{
			cir << "and: " << vAnd << "\n";
			cir << "or:  " << vOr << "\n";
			cir << "xor: " << vXor << "\n";
			cir << "not: " << vNot << "\n";
		}

		cir.output(vAnd);
		cir.output(vOr);
		cir.output(vXor);
		cir.output(vNot);

		cir.output(zAnd);
		cir.output(zOr);
		cir.output(zXor);
	}

	if (cir.mInputs.size() != 2)
		throw RTE_LOC;


	std::vector<BitVector> in(2), out;
	in[0].resize(1);
	in[1].resize(1);

	for (u64 a = 0; a < 2; ++a)
	{
		for (u64 b = 0; b < 2; ++b)
		{
			in[0][0] = a;
			in[1][0] = b;
			cir.evaluate(in, out);

			if (out[0][0] != (a & b))
				throw RTE_LOC;
			if (out[1][0] != (a | b))
				throw RTE_LOC;
			if (out[2][0] != (a ^ b))
				throw RTE_LOC;
			if (out[3][0] != (!a))
				throw RTE_LOC;


			if (out[4][0] != (a & 1))
				throw RTE_LOC;
			if (out[5][0] != (a | 1))
				throw RTE_LOC;
			if (out[6][0] != (a ^ 1))
				throw RTE_LOC;
		}
	}
}
template<typename T, typename V, typename ...Args>
void MxCircuit_int_Ops_Test(const oc::CLP& cmd, Args... args)
{
	bool verbose = cmd.isSet("verbose");
	Mx::Circuit cir;

	V cVal = 34212314;
	{
		auto a = cir.input<T>(args...);
		auto b = cir.input<T>(args...);
		auto c = T(args..., cVal);

		auto vAnd = a & b;
		auto vOr = a | b;
		auto vXor = a ^ b;
		auto vNot = !a;
		auto vrs = a >> 3;
		auto vls = a << 3;

		auto vPlus = a + b;
		auto vSub = a - b;

		auto vEqq = a == a;
		auto vEq = a == b;
		auto vNeq = a != b;
		auto vLt = a < b;
		auto vLtEq = a <= b;
		auto vGt = a > b;
		auto vGtEq = a >= b;

		auto zAnd = a & c;
		auto zOr = a | c;
		auto zXor = a ^ c;

		auto zPlus = a + c;
		auto zSub = a - c;
		auto zEq = a == c;
		auto zNeq = a != c;
		auto zLt = a < c;
		auto zLtEq = a <= c;
		auto zGt = a > c;
		auto zGtEq = a >= c;

		if (verbose)
		{

			cir << "a:   " << a << " " << a.asBits() << "\n";
			cir << "b:   " << b << " " << b.asBits() << "\n";
			cir << "c:   " << c << " " << c.asBits() << "\n";

			//cir << "and: " << vAnd << "\n";
			//cir << "or:  " << vOr << "\n";
			//cir << "xor: " << vXor << "\n";
			//cir << "not: " << vNot << "\n";

			//cir << "and: " << zAnd << " " << zAnd.asBits() << "\n";
			//cir << "or:  " << zOr << " " << zOr.asBits() << "\n";
			//cir << "xor: " << zXor << " " << zXor.asBits() << "\n";

			cir << "sub: " << zSub << "\n";
			cir << "lt:  " << zLt << "\n";

		}

		cir.output(vAnd);
		cir.output(vOr);
		cir.output(vXor);
		cir.output(vNot);
		cir.output(vrs);
		cir.output(vls);

		cir.output(vPlus);
		cir.output(vSub);

		cir.output(vEqq);
		cir.output(vEq);
		cir.output(vNeq);
		cir.output(vLt);
		cir.output(vLtEq);
		cir.output(vGt);
		cir.output(vGtEq);

		cir.output(zAnd);
		cir.output(zOr);
		cir.output(zXor);
		cir.output(zPlus);
		cir.output(zSub);
		cir.output(zEq);
		cir.output(zNeq);
		cir.output(zLt);
		cir.output(zLtEq);
		cir.output(zGt);
		cir.output(zGtEq);

	}

	if (cir.mInputs.size() != 2)
		throw RTE_LOC;


	std::vector<BitVector> in(2), out;
	in[0].resize(32);
	in[1].resize(32);

	PRNG prng(ZeroBlock);
	for (u64 i = 0; i < 10; ++i)
	{
		for (u64 j = 0; j < 10; ++j)
		{
			auto a = prng.get<V>();
			auto b = prng.get<V>();
			in[0].getSpan<V>()[0] = a;
			in[1].getSpan<V>()[0] = b;
			cir.evaluate(in, out);

			u64 k = 0;
			auto vAnd = out[k++].getSpan<V>()[0];
			auto vOr = out[k++].getSpan<V>()[0];
			auto vXor = out[k++].getSpan<V>()[0];
			bool vNot = out[k++][0];
			auto vrs = out[k++].getSpan<V>()[0];
			auto vls = out[k++].getSpan<V>()[0];

			auto vPlus = out[k++].getSpan<V>()[0];
			auto vSub = out[k++].getSpan<V>()[0];


			bool vEqq = out[k++][0];
			bool vEq = out[k++][0];
			bool vNeq = out[k++][0];
			bool vLt = out[k++][0];
			bool vLtEq = out[k++][0];
			bool vGt = out[k++][0];
			bool vGtEq = out[k++][0];


			auto zAnd = out[k++].getSpan<V>()[0];
			auto zOr = out[k++].getSpan<V>()[0];
			auto zXor = out[k++].getSpan<V>()[0];

			auto zPlus = out[k++].getSpan<V>()[0];
			auto zSub = out[k++].getSpan<V>()[0];
			bool zEq = out[k++][0];
			bool zNeq = out[k++][0];
			bool zLt = out[k++][0];
			bool zLtEq = out[k++][0];
			bool zGt = out[k++][0];
			bool zGtEq = out[k++][0];

			if (vAnd != (a & b))
				throw RTE_LOC;
			if (vOr != (a | b))
				throw RTE_LOC;
			if (vXor != (a ^ b))
				throw RTE_LOC;
			if (vNot != (!a))
				throw RTE_LOC;
			if (vrs != (a >> 3))
				throw RTE_LOC;
			if (vls != (a << 3))
				throw RTE_LOC;

			if (vPlus != (a + b))
				throw RTE_LOC;
			if (vSub != (a - b))
				throw RTE_LOC;

			if (!vEqq)
				throw RTE_LOC;
			if (vEq != (a == b))
				throw RTE_LOC;
			if (vNeq != (a != b))
				throw RTE_LOC;
			if (vLt != (a < b))
				throw RTE_LOC;
			if (vLtEq != (a <= b))
				throw RTE_LOC;
			if (vGt != (a > b))
				throw RTE_LOC;
			if (vGtEq != (a >= b))
				throw RTE_LOC;

			if (zAnd != (a & cVal))
				throw RTE_LOC;
			if (zOr != (a | cVal))
				throw RTE_LOC;
			if (zXor != (a ^ cVal))
				throw RTE_LOC;

			if (vPlus != (a + b))
				throw RTE_LOC;
			if (vSub != (a - b))
				throw RTE_LOC;

			if (zEq != (a == cVal))
				throw RTE_LOC;
			if (zNeq != (a != cVal))
				throw RTE_LOC;
			if (zLt != (a < cVal))
				throw RTE_LOC;
			if (zLtEq != (a <= cVal))
				throw RTE_LOC;
			if (zGt != (a > cVal))
				throw RTE_LOC;
			if (zGtEq != (a >= cVal))
				throw RTE_LOC;
		}
	}
}

void MxCircuit_BInt_Ops_Test(const oc::CLP& cmd)
{
	MxCircuit_int_Ops_Test<Mx::BInt<32>, i32>(cmd);
}

void MxCircuit_BUInt_Ops_Test(const oc::CLP& cmd)
{
	MxCircuit_int_Ops_Test<Mx::BUInt<32>, u32>(cmd);
}

void MxCircuit_BDynInt_Ops_Test(const oc::CLP& cmd)
{
	MxCircuit_int_Ops_Test<Mx::BDynInt, i32>(cmd, 32);
}

void MxCircuit_BDynUInt_Ops_Test(const oc::CLP& cmd)
{
	MxCircuit_int_Ops_Test<Mx::BDynUInt, u32>(cmd, 32);
}

void MxCircuit_Cast_Test(const oc::CLP& cmd)
{
	Mx::Circuit cir;

	auto a = cir.input<Mx::BInt<32>>();
	auto b = cir.input<Mx::BDynInt>(7);

	Mx::BDynInt d = a;
	Mx::BUInt<8> d8 = a;
	Mx::BInt<16> d16 = b;

	cir.output(d);
	cir.output(d8);
	cir.output(d16);

	PRNG prng(ZeroBlock);
	for (u64 i = 0; i < 10; ++i)
	{
		std::vector<BitVector> in(2), out;
		in[0].resize(a.size());
		in[1].resize(b.size());

		in[0].randomize(prng);
		in[1].randomize(prng);
		cir.evaluate(in, out);
		if (out[0] != in[0])
			throw RTE_LOC;

		for (u64 j = 0; j < out[1].size(); ++j)
			if (out[1][j] != in[0][j])
				throw RTE_LOC;
		for (u64 j = 0; j < out[1].size(); ++j)
			if (out[1][j] != in[0][j])
				throw RTE_LOC;
		for (u64 j = 0; j < out[1].size(); ++j)
			if (out[2][j] != in[1][std::min<u64>(j, in[1].size() - 1)])
				throw RTE_LOC;

	}

}

void MxCircuit_asBetaCircuit_Test(const oc::CLP& cmd)
{

	bool verbose = cmd.isSet("verbose");
	Mx::Circuit cir;
	using V = i32;
	V cVal = 34212314;
	{
		//auto c = Mx::BInt<32>(cVal);
		auto a = cir.input<Mx::Bit>();
		auto b = cir.input<Mx::Bit>();
		auto A = cir.input<Mx::BInt<32>>();
		auto B = cir.input<Mx::BInt<32>>();

		if (verbose)
			cir << "A " << A << "\nB " << B << "\n";

		auto x = a ^ b;
		cir.output(x);
		auto vPlus = A + B;
		auto vSub = A - B;
		if (verbose)
		{
			cir << "+ " << vPlus << "\n";
			cir << "- " << vSub << "\n";
		}

		cir.output(vPlus);
		cir.output(vSub);
	}

	auto bc = cir.asBetaCircuit();

	std::vector<BitVector> in(4), out(3);
	in[0].resize(1);
	in[1].resize(1);
	in[2].resize(32);
	in[3].resize(32);
	//in[4].resize(32);
	//in[5].resize(32);
	out[0].resize(1);
	out[1].resize(32);
	out[2].resize(32);
	PRNG prng(ZeroBlock);
	for (u64 i = 0; i < 4; ++i)
	{
		auto a = i % 2;
		auto b = i / 2;
		auto A = prng.get<i32>();
		auto B = prng.get<i32>();
		in[0][0] = a;
		in[1][0] = b;
		in[2].getSpan<i32>()[0] = A;
		in[3].getSpan<i32>()[0] = B;


		bc.evaluate(in, out);
		if (out[0][0] != (a ^ b))
			throw RTE_LOC;
		if (out[1].getSpan<i32>()[0] != (A + B))
			throw RTE_LOC;
		if (out[2].getSpan<i32>()[0] != (A - B))
			throw RTE_LOC;
	}

}

//struct PBit : Mx2::Bit<PBit>
//{
//	using value_type = bool;
//};
//
//struct PVBit : Mx2::Bit<PVBit>
//{
//	using value_type = std::vector<u8>;
//};
//
//void MxCircuit_plain_Bit_Test(const oc::CLP& cmd)
//{
//
//	bool verbose = cmd.isSet("verbose");
//	Mx::Circuit cir;
//
//	{
//		auto a = PVBit{};
//		auto b = PVBit{};
//		auto c = PVBit{};
//
//		auto vAnd = a & b;
//		auto vOr = a | b;
//		auto vXor = a ^ b;
//		auto vNot = !a;
//		auto zAnd = a & c;
//		auto zOr = a | c;
//		auto zXor = a ^ c;
//
//		//if (verbose)
//		//{
//		//	cir << "and: " << vAnd << "\n";
//		//	cir << "or:  " << vOr << "\n";
//		//	cir << "xor: " << vXor << "\n";
//		//	cir << "not: " << vNot << "\n";
//		//}
//
//		auto vAndOut = vAnd.output();
//		auto vOrOut = vOr.output();
//		auto vXorOut = vXor.output();
//		auto vNotOut = vNot.output();
//
//		auto zAndOut = zAnd.output();
//		auto zOrOut = zOr.output();
//		auto zXorOut = zXor.output();
//	}
//
//	if (cir.mInputs.size() != 2)
//		throw RTE_LOC;
//
//
//	std::vector<BitVector> in(2), out;
//	in[0].resize(1);
//	in[1].resize(1);
//
//	for (u64 a = 0; a < 2; ++a)
//	{
//		for (u64 b = 0; b < 2; ++b)
//		{
//			in[0][0] = a;
//			in[1][0] = b;
//			cir.evaluate(in, out);
//
//			if (out[0][0] != (a & b))
//				throw RTE_LOC;
//			if (out[1][0] != (a | b))
//				throw RTE_LOC;
//			if (out[2][0] != (a ^ b))
//				throw RTE_LOC;
//			if (out[3][0] != (!a))
//				throw RTE_LOC;
//
//
//			if (out[4][0] != (a & 1))
//				throw RTE_LOC;
//			if (out[5][0] != (a | 1))
//				throw RTE_LOC;
//			if (out[6][0] != (a ^ 1))
//				throw RTE_LOC;
//		}
//	}
//}