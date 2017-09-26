#include <cryptoTools/Common/BitIterator.h>

namespace osuCrypto
{

    BitReference::operator u8() const
    {
        return (*mByte & mMask) >> mShift;
    }

}
