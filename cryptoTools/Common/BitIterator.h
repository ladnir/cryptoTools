#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>

namespace osuCrypto
{

	// A class to reference a specific bit.
    class BitReference
    {
    public:

		// Default copy constructor
		BitReference(const BitReference& rhs) = default;

		// Construct a reference to the bit in the provided byte offset by the shift.
		// Shift should be less than 8.
        BitReference(u8* byte, u8 shift)
            :mByte(byte), mMask(1 << shift), mShift(shift) {}

		// Construct a reference to the bit in the provided byte offset by the shift and mask.
		// Shift should be less than 8. and the mask should equal 1 << shift.
        BitReference(u8* byte, u8 mask, u8 shift)
            :mByte(byte), mMask(mask), mShift(shift) {}

		// Copy the underlying values of the rhs to the lhs.
        void operator=(const BitReference& rhs) { *this = (u8)rhs; }

		// Copy the value of the rhs to the lhs.
		inline void operator=(u8 n) {
            if (n > 0)  *mByte |= mMask;
            else        *mByte &= ~mMask;
        }
		
		// Convert the reference to the underlying value
		operator u8() const {
			return (*mByte & mMask) >> mShift;
		}

	private:
		u8* mByte;
		u8 mMask, mShift;
    };

	// Function to allow the printing of a BitReference.
    std::ostream& operator<<(std::ostream& out, const BitReference& bit);

	// A class to allow the iteration of bits.
    class BitIterator
    {
    public:

		// Default copy constructor
		BitIterator(const BitIterator& cp) = default;

		// Construct a reference to the bit in the provided byte offset by the shift.
		// Shift should be less than 8.
        BitIterator(u8* byte, u8 shift)
            :mByte(byte), mMask(1 << shift), mShift(shift) {}

		// Construct a reference to the current bit pointed to by the iterator.
        BitReference operator*() { return BitReference(mByte, mMask, mShift); }

		// Pre increment the iterator by 1.
        BitIterator& operator++()
        {
            mByte += (mShift == 7) & 1;
            ++mShift &= 7;
            mMask = 1 << mShift;
            return *this;
        }

		// Post increment the iterator by 1. Returns a copy of this class.
        BitIterator operator++(int)
        {
            BitIterator ret(*this);

			mByte += (mShift == 7) & 1;
            ++mShift &= 7;
            mMask = 1 << mShift;

            return ret;
        }

		// Return the Iterator that has been incremented by v.
		// v must be possitive.
        BitIterator operator+(i64 v)const
        {
			Expects(v >= 0);

            BitIterator ret(*this);
            ret.mByte += (v / 8);
            ret.mShift += (v & 7);
            
            if (ret.mShift > 7) ++ret.mByte;
            
            ret.mShift &= 7;
            ret.mMask = 1 << mShift;

            return ret;
        }

		// Check if two iterators point to the same bit.
        bool operator==(const BitIterator& cmp)
        {
            return mByte == cmp.mByte && mShift == cmp.mShift;
        }

		u8* mByte;
		u8 mMask, mShift;
    };
}