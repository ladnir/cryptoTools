#pragma once

#if defined(USE_BLAKE2_AS_RANDOM_ORACLE) || !defined(ENABLE_NASM)

#include <cryptoTools/Crypto/Blake2.h>
namespace osuCrypto
{
	using RandomOracle = Blake2;
}
#else

#include <cryptoTools/Crypto/sha1.h>
namespace osuCrypto
{
	using RandomOracle = SHA1;
}
#endif