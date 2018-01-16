#include <cryptoTools/Crypto/Blake2.h>

namespace osuCrypto
{
	const u64 Blake2::HashSize;
	const u64 Blake2::MaxHashSize;

    const Blake2& Blake2::operator=(const Blake2& src)
    {
        state = src.state;
        return *this;
    }
}
