

#include "cryptoTools/Crypto/PRNG.h"

int main()
{
	using namespace oc;
	PRNG prng(oc::ZeroBlock);
	std::cout << prng.get<int>() << std::endl;
	return 0;
}