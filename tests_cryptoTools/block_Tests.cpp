#include "block_Tests.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Common/TestCollection.h"
#include <sstream>
#include "cryptoTools/Common/BitVector.h"

using namespace oc;

template<typename T>
std::string bits(T x, u64 width)
{
	std::stringstream ss;
	BitIterator iter((u8*)&x, 0);
	for (u64 i = 0; i < sizeof(T) * 8; ++i)
	{
		if (i && (i % width == 0))
			ss << " ";
		ss << *iter;

		++iter;
	}
	return ss.str();
}
//
//void mulTest(block a, block b)
//{
//
//    /* load the two operands and the modulus into 128-bit registers */
//    //const __m128i a = _mm_loadu_si128((const __m128i*) & (this->value_));
//    //const __m128i b = _mm_loadu_si128((const __m128i*) & (other.value_));
//    static const constexpr std::uint64_t mod = 0b10000111;
//    const __m128i modulus = _mm_loadl_epi64((const __m128i*) & mod);
//
//    /* compute the 256-bit result of a * b with the 64x64-bit multiplication
//       intrinsic */
//    block t4 = _mm_clmulepi64_si128(a, b, 0x11); /* high of both */
//    block t1 = _mm_clmulepi64_si128(a, b, 0x00);  /* low of both */
//
//    __m128i t3 =
//        _mm_clmulepi64_si128(a, b, 0x01); /* low of a, high of b */
//    __m128i t2 =
//        _mm_clmulepi64_si128(a, b, 0x10); /* high of a, low of b */
//
//    /* Add the 4 terms together */
//    t2 = _mm_xor_si128(t3, t2);
//    /* lower 64 bits of mid don't intersect with high, and upper 64 bits don't
//     * intersect with low */
//    t4 = _mm_xor_si128(t4, _mm_srli_si128(t2, 8));
//    t1 = _mm_xor_si128(t1, _mm_slli_si128(t2, 8));
//
//    std::array<block, 2> xx{ t1, t4 };
//    /* done computing t1 and t4, time to reduce */
//
//    /* reduce w.r.t. high half of t4 */
//    __m128i tmp = _mm_clmulepi64_si128(t4, modulus, 0x01);
//    t1 = _mm_xor_si128(t1, _mm_slli_si128(tmp, 8));
//    t4 = _mm_xor_si128(t4, _mm_srli_si128(tmp, 8));
//
//    /* reduce w.r.t. low half of t4 */
//    tmp = _mm_clmulepi64_si128(t4, modulus, 0x00);
//    t1 = _mm_xor_si128(t1, tmp);
//
//
//    std::cout << "\nexp *" << bits(xx, 128) << std::endl;
//    std::cout << "     " << bits(t1, 128) << std::endl;
//}
//
//static inline void mul128test(block x, block y)
//{
//    auto t1 = _mm_clmulepi64_si128(x, y, (int)0x00);
//    auto t2 = _mm_clmulepi64_si128(x, y, 0x10);
//    auto t3 = _mm_clmulepi64_si128(x, y, 0x01);
//    auto t4 = _mm_clmulepi64_si128(x, y, 0x11);
//
//    t2 = _mm_xor_si128(t2, t3);
//    t3 = _mm_slli_si128(t2, 8);
//    t2 = _mm_srli_si128(t2, 8);
//    t1 = _mm_xor_si128(t1, t3);
//    t4 = _mm_xor_si128(t4, t2);
//
//    auto xy1 = t1;
//    auto xy2 = t4;
//
//
//    std::array<block, 2> xx{ xy1, xy2 };
//    std::cout << "\nexp ^" << bits(xx, 128) << std::endl;
//}


void tests_cryptoTools::block_operation_test()
{

#ifdef OC_ENABLE_SSE2


	for (u64 i = 2; i < 100; ++i)
	{
		PRNG prng(block(i, 0));

		block x = prng.get();
		block y = prng.get();
		block z0, z1, q0, q1;

		u8 m64 = (prng.get<u8>() % 64);
		u8 m16 = (prng.get<u8>() % 16);

		int w0 = x.cc_movemask_epi8();
		int w1 = x.mm_movemask_epi8();
		if (w0 != w1)
		{
			std::cout << "movemask_epi8 " << i << std::endl;
			std::cout << "x   " << bits(x, 8) << std::endl;
			std::cout << "act " << bits(w0, 16) << std::endl;
			std::cout << "exp " << bits(w1, 16) << std::endl;

			//throw UnitTestFail("movemask_epi8 " LOCATION);
		}

		z0 = x.cc_add_epi64(y);
		z1 = x.mm_add_epi64(y);
		if (z0 != z1)
		{
			throw UnitTestFail("add_epi64 " LOCATION);
		}

		z0 = x.cc_and_si128(y);
		z1 = x.mm_and_si128(y);
		if (z0 != z1)
		{
			throw UnitTestFail("and_si128 " LOCATION);
		}

#ifdef OC_ENABLE_PCLMUL
		//mulTest(x, y);
		//mul128test(x, y);

		x.cc_gf128Mul(y, z0, z1);
		x.mm_gf128Mul(y, q0, q1);

		//auto r0 = z0.mm_gf128Reduce(z1);
		//auto r1 = q0.mm_gf128Reduce(q1);
		//if (r0 != r1)
		//{
		//    throw UnitTestFail("gf128Mul red 1 " LOCATION);
		//}
		auto r2 = z0.cc_gf128Reduce(z1);
		auto r3 = q0.cc_gf128Reduce(q1);
		if (r2 != r3)
		{
			throw UnitTestFail("gf128Mul red 2 " LOCATION);
		}
#endif

		z0 = x.cc_or_si128(y);
		z1 = x.mm_or_si128(y);
		if (z0 != z1)
		{
			throw UnitTestFail("or_si128 " LOCATION);
		}

		z0 = x.cc_slli_epi64(m64);
		z1 = x.mm_slli_epi64(m64);
		if (z0 != z1)
		{
			throw UnitTestFail("slli_epi64 " LOCATION);
		}

		z0 = x.cc_srai_epi16(m16);
		z1 = x.mm_srai_epi16(m16);
		if (z0 != z1)
		{
			std::cout << "srai_epi16 " << int(m16) << " " << i << std::endl;
			std::cout << "x   " << bits(x, 16) << std::endl;
			std::cout << "act " << bits(z0, 16) << std::endl;
			std::cout << "exp " << bits(z1, 16) << std::endl;
			throw UnitTestFail("srai_epi16 " LOCATION);
		}

		z0 = x.cc_xor_si128(y);
		z1 = x.mm_xor_si128(y);
		if (z0 != z1)
		{
			throw UnitTestFail("_cc_xor_si128 " LOCATION);
		}


		auto v0 = block(5);
		auto v1 = block(31);
		z0 = v0.cc_clmulepi64_si128<0x00>(v1);
		z1 = v0.mm_clmulepi64_si128<0x00>(v1);
		if (z0 != z1)
		{
			std::cout << std::hex << (5 * 31) << std::dec << "\n" << z0 << " " << bits(z0, 32) << std::endl;
			std::cout << z1 << " " << bits(z1, 32) << std::endl;
			throw RTE_LOC;
		}

		z0 = x.cc_clmulepi64_si128<0x00>(y);
		z1 = x.mm_clmulepi64_si128<0x00>(y);
		if (z0 != z1)
		{
			std::cout << "\n" << z0 << " " << bits(z0, 32) << std::endl;
			std::cout << z1 << " " << bits(z1, 32) << std::endl;
			throw RTE_LOC;
		}
		z0 = x.cc_clmulepi64_si128<0x01>(y);
		z1 = x.mm_clmulepi64_si128<0x01>(y);
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_clmulepi64_si128<0x10>(y);
		z1 = x.mm_clmulepi64_si128<0x10>(y);
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_clmulepi64_si128<0x11>(y);
		z1 = x.mm_clmulepi64_si128<0x11>(y);
		if (z0 != z1)
			throw RTE_LOC;




		z0 = x.cc_unpacklo_epi64(y);
		z1 = x.mm_unpacklo_epi64(y);
		if (z0 != z1)
			throw RTE_LOC;




		z0 = x.cc_srli_si128<0>();
		z1 = x.mm_srli_si128<0>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_srli_si128<3>();
		z1 = x.mm_srli_si128<3>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_srli_si128<11>();
		z1 = x.mm_srli_si128<11>();
		if (z0 != z1)
			throw RTE_LOC;



		z0 = x.cc_slli_si128<0>();
		z1 = x.mm_slli_si128<0>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_slli_si128<3>();
		z1 = x.mm_slli_si128<3>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_slli_si128<11>();
		z1 = x.mm_slli_si128<11>();
		if (z0 != z1)
			throw RTE_LOC;


		z0 = x.cc_shuffle_epi32<0b10110010>();
		z1 = x.mm_shuffle_epi32<0b10110010>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_shuffle_epi32<0b00100011>();
		z1 = x.mm_shuffle_epi32<0b00100011>();
		if (z0 != z1)
			throw RTE_LOC;




		z0 = x.cc_srai_epi32<0>();
		z1 = x.mm_srai_epi32<0>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_srai_epi32<1>();
		z1 = x.mm_srai_epi32<1>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_srai_epi32<7>();
		z1 = x.mm_srai_epi32<7>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_srai_epi32<18>();
		z1 = x.mm_srai_epi32<18>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_srai_epi32<32>();
		z1 = x.mm_srai_epi32<32>();
		if (z0 != z1)
		{
			std::cout << "act " << z0 << std::endl;
			std::cout << "exp " << z1 << std::endl;
			throw RTE_LOC;
		}
		z0 = x.cc_srai_epi32<40>();
		z1 = x.mm_srai_epi32<40>();
		if (z0 != z1)
			throw RTE_LOC;



		z0 = x.cc_slli_epi32<0>();
		z1 = x.mm_slli_epi32<0>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_slli_epi32<1>();
		z1 = x.mm_slli_epi32<1>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_slli_epi32<7>();
		z1 = x.mm_slli_epi32<7>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_slli_epi32<18>();
		z1 = x.mm_slli_epi32<18>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_slli_epi32<32>();
		z1 = x.mm_slli_epi32<32>();
		if (z0 != z1)
			throw RTE_LOC;
		z0 = x.cc_slli_epi32<40>();
		z1 = x.mm_slli_epi32<40>();
		if (z0 != z1)
			throw RTE_LOC;




	}
#endif

}
