#include "MxCircuit_Tests.h"
#include "cryptoTools/Circuit/MxCircuit.h"
#include "cryptoTools/Circuit/MxCircuitLibrary.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Circuit/MxTypes.h"

using namespace oc;
i64 signExtend(i64 v, u64 b, bool print = false);

void MxCircuit_Bit_Ops_Test()
{
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

		cir << "and: " << vAnd << "\n";
		cir << "or:  " << vOr << "\n";
		cir << "xor: " << vXor << "\n";
		cir << "not: " << vNot << "\n";


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


	std::vector<BitVector> in(2), out(4);
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



//
//void MxCircuit_SequentialOp_Test()
//{
//
//	PRNG prng(ZeroBlock);
//	u64 tries = 100;
//
//
//	for (u64 i = 0; i < tries; ++i)
//	{
//
//		u64 aSize = prng.get<u32>() % 24 + 1,
//			bSize = prng.get<u32>() % 24 + 1,
//			cSize = std::min<u64>(prng.get<u32>() % 24 + 1, std::max(aSize, bSize) + 1);
//
//		Mx::parallelPrefix()
//		auto* cirAdd = int_int_add(aSize, bSize, cSize);
//		//auto* cirNeg = lib.int_negate(aSize);
//		auto* cirInv = lib.int_bitInvert(aSize);
//
//
//		i64 a = signExtend(prng.get<i64>(), aSize);
//		i64 b = signExtend(prng.get<i64>(), bSize);
//		i64 c = signExtend((~a + b), cSize);
//
//		std::vector<BitVector> invInputs(1), invOutput(1);
//		invInputs[0].append((u8*)&a, aSize);
//		invOutput[0].resize(aSize);
//
//		cirInv->evaluate(invInputs, invOutput);
//
//
//		std::vector<BitVector> addInputs(2), addOutput(1);
//		addInputs[0] = invOutput[0];
//		addInputs[1].append((u8*)&b, bSize);
//		addOutput[0].resize(cSize);
//
//
//
//		cirAdd->evaluate(addInputs, addOutput);
//
//		i64 cc = 0;
//		memcpy(&cc, addOutput[0].data(), addOutput[0].sizeBytes());
//
//		cc = signExtend(cc, cSize);
//
//		if (cc != c)
//		{
//			std::cout << "i " << i << std::endl;
//
//			BitVector cExp;
//			cExp.append((u8*)&c, cSize);
//			std::cout << "a  : " << invInputs[0] << std::endl;
//			std::cout << "~a : " << addInputs[0] << std::endl;
//			std::cout << "b  : " << addInputs[1] << std::endl;
//			std::cout << "exp: " << cExp << std::endl;
//			std::cout << "act: " << addOutput[0] << std::endl;
//
//			throw RTE_LOC;
//		}
//
//	}
//}
