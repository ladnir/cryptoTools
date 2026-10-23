//#include "stdafx.h"

#include <thread>
#include <vector>
#include <memory>

#include "Common.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/AES.h> 
#include <cryptoTools/Common/Log.h>

namespace osuCrypto
{
    void aesCheck();
}
using namespace osuCrypto;
//namespace tests_cryptoTools
//{
#include <iomanip>
namespace tests_cryptoTools
{
	template<u64 n, class Cipher>
	void checkFixedBatch(const Cipher& aes, const block* input)
	{
		alignas(32) block storage[n + 2];
		// Deliberately only 16-byte aligned, with guards on both sides.
		auto out = storage + 1;
		storage[0] = storage[n + 1] = block(123);
		aes.template ecbEncBlocks<n>(input, out);
		for (u64 i = 0; i < n; ++i)
			if (out[i] != aes.ecbEncBlock(input[i])) throw UnitTestFail();
		std::copy(input, input + n, out);
		aes.template ecbEncBlocks<n>(out, out);
		for (u64 i = 0; i < n; ++i)
			if (out[i] != aes.ecbEncBlock(input[i])) throw UnitTestFail();
		aes.template hashBlocks<n>(input, out);
		for (u64 i = 0; i < n; ++i)
			if (out[i] != (aes.ecbEncBlock(input[i]) ^ input[i])) throw UnitTestFail();
		std::copy(input, input + n, out);
		aes.template hashBlocks<n>(out, out);
		for (u64 i = 0; i < n; ++i)
			if (out[i] != (aes.ecbEncBlock(input[i]) ^ input[i])) throw UnitTestFail();
		if (storage[0] != block(123) || storage[n + 1] != block(123)) throw UnitTestFail();
		if constexpr (n > 1) checkFixedBatch<n - 1>(aes, input);
	}

	template<class Cipher>
	void checkBatches(const Cipher& aes)
	{
		alignas(32) block inputStorage[259], outputStorage[259];
		auto input = inputStorage + 1;
		auto out = outputStorage + 1;
		for (u64 i = 0; i < 257; ++i) input[i] = block(12345 * i, 67890 + i);
		checkFixedBatch<32>(aes, input);
		for (u64 n = 0; n <= 257; ++n)
		{
			outputStorage[0] = out[n] = block(123);
			for (bool hash : {false, true})
				for (bool inplace : {false, true})
				{
					std::copy(input, input + n, out);
					const block* src = inplace ? out : input;
					if (hash) aes.hashBlocks(src, n, out);
					else aes.ecbEncBlocks(src, n, out);
					for (u64 i = 0; i < n; ++i)
						if (out[i] != (aes.ecbEncBlock(input[i]) ^ (hash ? input[i] : ZeroBlock)))
							throw UnitTestFail();
					if (outputStorage[0] != block(123) || out[n] != block(123)) throw UnitTestFail();
				}
		}
	}

	block byteReverse(block b)
	{
		block r;
		auto bb = b.data();
		auto rr = r.data();
		for (u64 i = 0; i < 16; ++i)
			rr[i] = bb[15 - i];
		return r;
	}

	template<details::AESTypes type>
	void test()
	{

		block userKey = byteReverse(toBlock(
			0x0001020304050607,
			0x08090a0b0c0d0e0f));
		block ptxt = byteReverse(toBlock(
			0x0011223344556677,
			0x8899aabbccddeeff));
		block exp = byteReverse(toBlock(
			0x69c4e0d86a7b0430,
			0xd8cdb78070b4c55a));

		details::AES<type> encKey(userKey);
		checkBatches(encKey);
		//details::AES<details::Portable> encKey2(userKey);

		auto ctxt = encKey.ecbEncBlock(ptxt);
		if (neq(ctxt, exp))
			throw UnitTestFail();

		details::AESDec<type> decKey(userKey);

		auto ptxt2 = decKey.ecbDecBlock(ctxt);
		if (neq(ptxt2, ptxt))
			throw UnitTestFail();

		for (u64 tt = 0; tt < 40; ++tt)
		{
			u64 length = (1ull << 6) + tt;

			std::vector<block> data(length);
			std::vector<block> cyphertext1(length);
			std::vector<block> cyphertext2(length);

			for (u64 i = 0; i < length; ++i)
			{
				data[i] = toBlock(i);
				encKey.ecbEncBlock(data[i], cyphertext1[i]);
				decKey.ecbDecBlock(cyphertext1[i], ptxt);
				if (neq(data[i], ptxt))
					throw UnitTestFail();
			}

			encKey.ecbEncBlocks(data.data(), data.size(), cyphertext2.data());
			for (u64 i = 0; i < length; ++i)
			{
				if (neq(cyphertext1[i], cyphertext2[i]))
					throw UnitTestFail();
			}

			encKey.ecbEncCounterMode(1423234, data.size(), cyphertext2.data());
			for (u64 i = 0; i < length; ++i)
			{
				if (neq(encKey.ecbEncBlock(block(1423234 + i)), cyphertext2[i]))
					throw UnitTestFail();
			}

			u64 step = 3;
			std::vector<block> data2(length * step);
			for (u64 i = 0; i < length; ++i)
			{
				for (u64 j = 0; j < step; ++j)
				{
					data2[i * step + j] = block(45233453 * i, 234235543 * j);
				}

				data[i] = data2[i * step + (i % step)];
			}

			encKey.TmmoHashBlocks(data, cyphertext1, [t = 0]() mutable {return block(t++); });
			encKey.TmmoHashBlocks(data, cyphertext2, [t = 0]() mutable {return block(t++); });

			for (u64 i = 0; i < length; ++i)
			{

				if (cyphertext1[i] != cyphertext2[i])
				{
					throw RTE_LOC;
				}

				// y_i = AES(AES(x_i) ^ tweak_i) + AES(x_i).
				if (cyphertext1[i] != (encKey.ecbEncBlock(encKey.ecbEncBlock(data[i]) ^ block(i)) ^ encKey.ecbEncBlock(data[i])))
					throw RTE_LOC;

				if (cyphertext1[i] != encKey.TmmoHashBlock(data[i], block(i)))
					throw RTE_LOC;
			}

			cyphertext2.resize(data2.size());
			encKey.TmmoHashBlocks(data2, cyphertext2, [t = 0, step]() mutable {return block(t++ / step); });

			for (u64 i = 0; i < length; ++i)
			{
				if (cyphertext1[i] != cyphertext2[i * step + (i % step)])
				{
					throw RTE_LOC;
				}
			}
		}

		{
			block state(241453245234532ull, 2345123451235123ull);
			block t = details::AES<type>::roundEnc(state, state);
			//std::cout << t.get<u64>(1) << std::endl;
			//std::cout << t.get<u64>(0) << std::endl;
			block exp(7833415616886348363ull, 14916852119338822067ull);
			if (t != exp)
				throw RTE_LOC;
		}
	}



	template<details::AESTypes type0, details::AESTypes type1>
	void compare()
	{
		block userKey(2342134234, 213421341234);
		details::AES<type0> enc0(userKey);
		details::AES<type1> enc1(userKey);


		for (u64 i = 0; i < 40; ++i)
		{
			auto b0 = enc0.ecbEncBlock(block(324223, i));
			auto b1 = enc1.ecbEncBlock(block(324223, i));

			if (b0 != b1)
				throw RTE_LOC;
		}
	}
    
	void AES_EncDec_Test()
	{

#ifdef OC_ENABLE_PORTABLE_AES
		test<details::AESTypes::Portable>();
#endif // ENABLE_PORTABLE_AES
#ifdef OC_ENABLE_AESNI
		test<details::AESTypes::NI>();
#endif // ENABLE_SSE
#ifdef ENABLE_ARM_AES
		test<details::AESTypes::ARM>();
#endif // ENABLE_ARM_AES

#if defined(OC_ENABLE_AESNI) && defined(OC_ENABLE_PORTABLE_AES)
		compare<details::AESTypes::NI, details::AESTypes::Portable>();
#endif

#if defined(ENABLE_ARM_AES) && defined(OC_ENABLE_PORTABLE_AES)
		compare<details::AESTypes::ARM, details::AESTypes::Portable>();
#endif

}

}
