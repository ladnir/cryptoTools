#include "MxCircuit_Tests.h"
#include "Circuit_Tests.h"

#include "cryptoTools/Circuit/MxCircuit.h"
#include "cryptoTools/Circuit/MxCircuitLibrary.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Circuit/MxTypes.h"
#include "cryptoTools/Common/TestCollection.h"


using namespace oc;

void MxCircuit_Bit_Ops_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_CIRCUITS

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
#else
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
#endif
}


template<typename T, typename V, typename ...Args>
void MxCircuit_int_Ops_Test(const oc::CLP& cmd, Args... args)
{
#ifdef ENABLE_CIRCUITS

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
		auto vNeg = -a;
		auto vMult = a * b;
		auto vDiv = a / b;
		auto vRem = a % b;

		auto vEqq = a == a;
		auto vEq = a == b;
		auto vNeq = a != b;
		auto vLt = a < b;
		auto vLtEq = a <= b;
		auto vGt = a > b;
		auto vGtEq = a >= b;

		auto vSel = vGt.select(a, b);

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
		cir.output(vNeg);
		cir.output(vMult);
		cir.output(vDiv);
		cir.output(vRem);

		cir.output(vEqq);
		cir.output(vEq);
		cir.output(vNeq);
		cir.output(vLt);
		cir.output(vLtEq);
		cir.output(vGt);
		cir.output(vGtEq);

		cir.output(vSel);

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
			auto vNeg = out[k++].getSpan<V>()[0];
			auto vMult = out[k++].getSpan<V>()[0];
			auto vDiv = out[k++].getSpan<V>()[0];
			auto vRem = out[k++].getSpan<V>()[0];


			bool vEqq = out[k++][0];
			bool vEq = out[k++][0];
			bool vNeq = out[k++][0];
			bool vLt = out[k++][0];
			bool vLtEq = out[k++][0];
			bool vGt = out[k++][0];
			bool vGtEq = out[k++][0];

			auto vSel = out[k++].getSpan<V>()[0];


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
			if (vNeg != -a)
				throw RTE_LOC;
			if (vMult != (a * b))
				throw RTE_LOC;
			if (b && vDiv != (a / b))
				throw RTE_LOC;
			if (b && vRem != (a % b))
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


			if (vSel != ((a > b) ?  a : b))
				throw RTE_LOC;

			if (zAnd != (a & cVal))
				throw RTE_LOC;
			if (zOr != (a | cVal))
				throw RTE_LOC;
			if (zXor != (a ^ cVal))
				throw RTE_LOC;

			if (zPlus != (a + cVal))
				throw RTE_LOC;
			if (zSub != (a - cVal))
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

#else
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
#endif
}

void MxCircuit_BInt_Ops_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_CIRCUITS
	MxCircuit_int_Ops_Test<Mx::BInt<32>, i32>(cmd);
#else
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
#endif
}

void MxCircuit_BUInt_Ops_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_CIRCUITS
	MxCircuit_int_Ops_Test<Mx::BUInt<32>, u32>(cmd);
#else
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
#endif
}

void MxCircuit_BDynInt_Ops_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_CIRCUITS
	MxCircuit_int_Ops_Test<Mx::BDynInt, i32>(cmd, 32);
#else
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
#endif
}

void MxCircuit_BDynUInt_Ops_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_CIRCUITS
	MxCircuit_int_Ops_Test<Mx::BDynUInt, u32>(cmd, 32);
#else
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
#endif
}

void MxCircuit_Cast_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_CIRCUITS

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

#else
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
#endif
}

void MxCircuit_asBetaCircuit_Test(const oc::CLP& cmd)
{
#ifdef ENABLE_CIRCUITS

	bool verbose = cmd.isSet("verbose");
	PRNG prng(ZeroBlock);
	auto trials = cmd.getOr("trials", 1ull);
	for (u64 t = 0; t < trials; ++t)
	{

		Mx::Circuit cir;
		{
			auto a = cir.input<Mx::Bit>();
			auto b = cir.input<Mx::Bit>();
			auto A = cir.input<Mx::BInt<64>>();
			auto B = cir.input<Mx::BInt<64>>();

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
		in[2].resize(64);
		in[3].resize(64);
		//in[4].resize(64);
		//in[5].resize(64);
		out[0].resize(1);
		out[1].resize(64);
		out[2].resize(64);
		for (u64 i = 0; i < 4; ++i)
		{
			auto a = i % 2;
			auto b = i / 2;
			auto A = prng.get<i64>();
			auto B = prng.get<i64>();
			in[0][0] = a;
			in[1][0] = b;
			in[2].getSpan<i64>()[0] = A;
			in[3].getSpan<i64>()[0] = B;


			bc.evaluate(in, out);
			if (out[0][0] != (a ^ b))
				throw RTE_LOC;
			if (out[1].getSpan<i64>()[0] != (A + B))
			{
				std::cout << "\nact " << out[1].getSpan<i64>()[0] << "\n";
				std::cout << "exp " << (A + B) << std::endl;;
				throw RTE_LOC;
			}
			if (out[2].getSpan<i64>()[0] != (A - B))
				throw RTE_LOC;
		}
	}
#else
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
#endif
}

template<typename T>
T signEx(T v, u64 s)
{
	if (s == sizeof(T) * 8)
		return v;

	i64 sign = *BitIterator((u8*)&v, s - 1);

	if (sign && std::is_signed_v<T>)
	{
		T mask = T(std::make_unsigned_t<T>(-1) << s);
		return v | mask;
	}
	else
	{
		T mask = (T(1) << s) - 1;
		auto ret = v & mask;
		return ret;
	}
}

#ifdef ENABLE_CIRCUITS

template<typename T>
void MxCircuit_parallelPrefix_impl(u64 trials, Mx::AdderType at, PRNG& prng)
{
	auto type = std::is_signed_v<T> ? Mx::IntType::TwosComplement : Mx::IntType::Unsigned;
	for (u64 i = 0; i < trials; ++i)
	{
		auto s0 = (prng.get<u32>() % 64) + 1;
		auto s1 = (prng.get<u32>() % 64) + 1;
		auto s2 = (prng.get<u32>() % 64) + 1;


		Mx::Circuit cir;
		auto A = cir.input<Mx::BVector>(s0);
		auto B = cir.input<Mx::BVector>(s1);
		Mx::BVector C(s2);
		Mx::parallelPrefix(A, B, C, type, at);
		cir.output(C);


		std::vector<BitVector> in(2), out(1);
		in[0].resize(s0);
		in[1].resize(s1);
		out[0].resize(s2);
		for (u64 j = 0; j < 1; ++j)
		{
			T a = signEx(prng.get<T>(), s0);
			T b = signEx(prng.get<T>(), s1);
			T c = at == Mx::AdderType::Addition ?
				a + b :
				a - b;

			c = signEx(c, s2);

			memcpy(in[0].data(), &a, in[0].sizeBytes());
			memcpy(in[1].data(), &b, in[1].sizeBytes());

			cir.evaluate(in, out);

			T cAct = 0;
			memcpy(&cAct, out[0].data(), out[0].sizeBytes());
			cAct = signEx(cAct, s2);

			if (c != cAct)
			{
				std::cout << " exp " << c << "\t" << BitVector((u8*)&c, s2) << "\n";
				std::cout << " act " << cAct << "\t" << BitVector((u8*)&cAct, s2) << "\n";
				throw RTE_LOC;
			}
		}
	}

}

void MxCircuit_parallelPrefix_Test(const oc::CLP& cmd)
{
	PRNG prng(ZeroBlock);
	auto trials = cmd.getOr<u64>("trials", 100);

	MxCircuit_parallelPrefix_impl<u64>(trials, Mx::AdderType::Addition, prng);
	MxCircuit_parallelPrefix_impl<u64>(trials, Mx::AdderType::Subtraction, prng);
	MxCircuit_parallelPrefix_impl<i64>(trials, Mx::AdderType::Addition, prng);
	MxCircuit_parallelPrefix_impl<i64>(trials, Mx::AdderType::Subtraction, prng);
}



template<typename T>
void MxCircuit_rippleAdder_impl(u64 trials, Mx::AdderType at, PRNG& prng)
{
	auto type = std::is_signed_v<T> ? Mx::IntType::TwosComplement : Mx::IntType::Unsigned;
	for (u64 i = 0; i < trials; ++i)
	{
		auto s0 = (prng.get<u32>() % 64) + 1;
		auto s1 = (prng.get<u32>() % 64) + 1;
		auto s2 = (prng.get<u32>() % 64) + 1;


		Mx::Circuit cir;
		auto A = cir.input<Mx::BVector>(s0);
		auto B = cir.input<Mx::BVector>(s1);
		Mx::BVector C(s2);
		Mx::rippleAdder(A, B, C, type, at);
		cir.output(C);


		std::vector<BitVector> in(2), out(1);
		in[0].resize(s0);
		in[1].resize(s1);
		out[0].resize(s2);
		for (u64 j = 0; j < 10; ++j)
		{
			T a = signEx(prng.get<T>(), s0);
			T b = signEx(prng.get<T>(), s1);
			T c = at == Mx::AdderType::Addition ?
				a + b :
				a - b;

			c = signEx(c, s2);

			memcpy(in[0].data(), &a, in[0].sizeBytes());
			memcpy(in[1].data(), &b, in[1].sizeBytes());

			cir.evaluate(in, out);

			T cAct = 0;
			memcpy(&cAct, out[0].data(), out[0].sizeBytes());
			cAct = signEx(cAct, s2);

			if (c != cAct)
			{
				std::cout << cir << std::endl;

				std::cout << "\n exp " << c << "\t" << BitVector((u8*)&c, s2) << "\n";
				std::cout << " act " << cAct << "\t" << BitVector((u8*)&cAct, s2) << "\n";
				throw RTE_LOC;
			}
		}
	}

}

void MxCircuit_rippleAdder_Test(const oc::CLP& cmd)
{
	PRNG prng(ZeroBlock);
	auto trials = cmd.getOr<u64>("trials", 100);

	MxCircuit_rippleAdder_impl<u64>(trials, Mx::AdderType::Addition, prng);
	MxCircuit_rippleAdder_impl<u64>(trials, Mx::AdderType::Subtraction, prng);
	MxCircuit_rippleAdder_impl<i64>(trials, Mx::AdderType::Addition, prng);
	MxCircuit_rippleAdder_impl<i64>(trials, Mx::AdderType::Subtraction, prng);
}



template<typename T>
void MxCircuit_parallelSummation_impl(u64 trials, Mx::Optimized op, PRNG& prng)
{
	auto type = std::is_signed_v<T> ? Mx::IntType::TwosComplement : Mx::IntType::Unsigned;
	for (u64 i = 0; i < trials; ++i)
	{
		u64 numTerms = (prng.get<u32>() % 16 + 1);
		auto s0 = (prng.get<u32>() % 16) + 1;

		Mx::Circuit cir;
		std::vector<Mx::BVector> X(numTerms);
		std::vector<T>x(numTerms);
		std::vector<span<const Mx::Bit>> bits(numTerms);
		std::vector<BitVector> in(numTerms), out(1);

		for (u64 i = 0; i < numTerms; ++i)
		{
			auto s = s0;// (prng.get<u32>() % 64) + 1;
			in[i].resize(s);
			X[i] = cir.input<Mx::BVector>(s);
			bits[i] = X[i].asBits();
		}

		out[0].resize(s0);
		Mx::BVector C(s0);
		Mx::parallelSummation(bits, C.asBits(), op, type);
		cir.output(C);

		for (u64 j = 0; j < 10; ++j)
		{
			T c = 0;
			for (u64 i = 0; i < numTerms; ++i)
			{
				x[i] = signEx(prng.get<T>(), X[i].size());
				memcpy(in[i].data(), &x[i], in[i].sizeBytes());
				c += x[i];
			}
			c = signEx(c, s0);

			cir.evaluate(in, out);

			T cAct = 0;
			memcpy(&cAct, out[0].data(), out[0].sizeBytes());
			cAct = signEx(cAct, s0);

			if (c != cAct)
			{
				//std::cout << cir << std::endl;

				std::cout << "\n exp " << c << "\t" << BitVector((u8*)&c, s0) << "\n";
				std::cout << " act " << cAct << "\t" << BitVector((u8*)&cAct, s0) << "\n";
				throw RTE_LOC;
			}
		}
	}
}


void MxCircuit_parallelSummation_Test(const oc::CLP& cmd)
{

	PRNG prng(ZeroBlock);
	auto trials = cmd.getOr<u64>("trials", 10);

	MxCircuit_parallelSummation_impl<u64>(trials, Mx::Optimized::Depth, prng);
	MxCircuit_parallelSummation_impl<u64>(trials, Mx::Optimized::Size, prng);
	MxCircuit_parallelSummation_impl<i64>(trials, Mx::Optimized::Depth, prng);
	MxCircuit_parallelSummation_impl<i64>(trials, Mx::Optimized::Size, prng);
}



template<typename T>
void MxCircuit_multiply_impl(u64 trials, Mx::Optimized op, PRNG& prng)
{
	auto type = std::is_signed_v<T> ? Mx::IntType::TwosComplement : Mx::IntType::Unsigned;
	for (u64 i = 0; i < trials; ++i)
	{
		auto s0 = (prng.get<u32>() % 16) + 1;
		auto s1 = (prng.get<u32>() % 16) + 1;
		auto s2 = (prng.get<u32>() % 16) + 1;

		Mx::Circuit cir;
		auto A = cir.input<Mx::BVector>(s0);
		auto B = cir.input<Mx::BVector>(s1);
		Mx::BVector C(s2);
		Mx::multiply(A, B, C, op, type);
		cir.output(C);


		std::vector<BitVector> in(2), out(1);
		in[0].resize(s0);
		in[1].resize(s1);
		out[0].resize(s2);
		for (u64 j = 0; j < 10; ++j)
		{
			T a = signEx(prng.get<T>(), s0);
			T b = signEx(prng.get<T>(), s1);
			T c = a * b;
			//if (i != 7 || j != 5)
			//	continue;
			c = signEx(c, s2);

			memcpy(in[0].data(), &a, in[0].sizeBytes());
			memcpy(in[1].data(), &b, in[1].sizeBytes());
			//std::cout << "\n\n========================\n";
			cir.evaluate(in, out);

			T cAct = 0;
			memcpy(&cAct, out[0].data(), out[0].sizeBytes());
			cAct = signEx(cAct, s2);

			if (c != cAct)
			{
				std::cout << "\n exp " << c << "\t" << BitVector((u8*)&c, s2) << "\n";
				std::cout << " act " << cAct << "\t" << BitVector((u8*)&cAct, s2) << "\n";
				throw RTE_LOC;
			}
		}
	}
}



void MxCircuit_multiply_Test(const oc::CLP& cmd)
{
	PRNG prng(ZeroBlock);
	auto trials = cmd.getOr<u64>("trials", 100);

	MxCircuit_multiply_impl<u64>(trials, Mx::Optimized::Depth, prng);
	MxCircuit_multiply_impl<u64>(trials, Mx::Optimized::Size, prng);
	MxCircuit_multiply_impl<i64>(trials, Mx::Optimized::Depth, prng);
	MxCircuit_multiply_impl<i64>(trials, Mx::Optimized::Size, prng);
}


template<typename T>
void MxCircuit_divideRemainder_impl(u64 trials, Mx::Optimized op, PRNG& prng)
{
	auto type = std::is_signed_v<T> ? Mx::IntType::TwosComplement : Mx::IntType::Unsigned;
	for (u64 i = 0; i < trials; ++i)
	{
		auto s0 = (prng.get<u32>() % 8) + 1;
		auto s1 = (prng.get<u32>() % 8) + 1;

		Mx::Circuit cir;
		auto A = cir.input<Mx::BVector>(s0);
		auto B = cir.input<Mx::BVector>(s1);
		Mx::BVector Q(s0), R(s0);
		Mx::divideRemainder(A, B, Q, R, op, type);
		cir.output(Q);
		cir.output(R);


		std::vector<BitVector> in(2), out(1);
		in[0].resize(s0);
		in[1].resize(s1);
		out[0].resize(s0);
		for (u64 j = 0; j < 10; ++j)
		{
			T a = signEx(prng.get<T>(), s0);
			T b = 0;
			while (b == 0)
				b = signEx(prng.get<T>(), s1);
			T q = a / b;
			T r = a % b;
			//if (i != 6 || j != 5)
			//	continue;
			q = signEx(q, s0);
			r = signEx(r, s0);

			memcpy(in[0].data(), &a, in[0].sizeBytes());
			memcpy(in[1].data(), &b, in[1].sizeBytes());

			cir.evaluate(in, out);

			T qAct = 0, rAct = 0;
			memcpy(&qAct, out[0].data(), out[0].sizeBytes());
			qAct = signEx(qAct, s0);
			memcpy(&rAct, out[1].data(), out[1].sizeBytes());
			rAct = signEx(rAct, s0);

			if (q != qAct)
			{
				std::cout << "\nA " << a << "\t" << BitVector((u8*)&a, s0) << "\n";
				std::cout << "B " << b << "\t" << BitVector((u8*)&b, s1) << "\n";
				std::cout << "Q\n exp " << q << "\t" << BitVector((u8*)&q, s0) << "\n";
				std::cout << " act " << qAct << "\t" << BitVector((u8*)&qAct, s0) << "\n";
				throw RTE_LOC;
			}
			if (r != rAct)
			{
				std::cout << "\nR\n exp " << r << "\t" << BitVector((u8*)&r, s0) << "\n";
				std::cout << " act " << rAct << "\t" << BitVector((u8*)&rAct, s0) << "\n";
				throw RTE_LOC;
			}
		}
	}
}


void MxCircuit_divideRemainder_Test(const oc::CLP& cmd)
{

	PRNG prng(ZeroBlock);
	auto trials = cmd.getOr<u64>("trials", 20);

	MxCircuit_divideRemainder_impl<u64>(trials, Mx::Optimized::Depth, prng);
	MxCircuit_divideRemainder_impl<u64>(trials, Mx::Optimized::Size, prng);
	MxCircuit_divideRemainder_impl<i64>(trials, Mx::Optimized::Depth, prng);
	MxCircuit_divideRemainder_impl<i64>(trials, Mx::Optimized::Size, prng);
}
#else
void MxCircuit_parallelPrefix_Test(const oc::CLP& cmd)
{
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
}
void MxCircuit_rippleAdder_Test(const oc::CLP& cmd)
{
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
}
void MxCircuit_parallelSummation_Test(const oc::CLP& cmd)
{
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
}
void MxCircuit_multiply_Test(const oc::CLP& cmd)
{
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
}
void MxCircuit_divideRemainder_Test(const oc::CLP& cmd)
{
	throw UnitTestSkipped("ENABLE_CIRCUITS=false");
}

#endif
