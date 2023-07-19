#include <cryptoTools/Common/BitVector.h>
#include <sstream>
#include <cstring>
#include <iomanip>
//#include <atomic>

namespace osuCrypto {

	//namespace detail
	//{
	//	std::atomic<int> aligned_allocator_count(0);
	//}

	BitVector::BitVector(std::string data)
	{
		fromString(data);
	}

	BitVector::BitVector(u8* data, u64 length)
	{
		append(data, length, 0);
	}

	void BitVector::assign(const block& b)
	{
		reset(128);
		mData[0] = b;
	}

	void BitVector::assign(const BitVector& K)
	{
		reset(K.mNumBits);
		std::copy_n(K.mData.get(), sizeBlocks(), mData.get());
	}

	void BitVector::append(u8* dataIn, u64 length, u64 offset)
	{

		auto bitIdx = mNumBits;
		auto destOffset = mNumBits % 8;
		auto destIdx = mNumBits / 8;
		auto srcOffset = offset % 8;
		auto srcIdx = offset / 8;
		auto byteLength = (length + 7) / 8;

		resize(mNumBits + length);

		static const u8 masks[8] = { 1,2,4,8,16,32,64,128 };

		// if we have to do bit shifting, copy bit by bit
		if (srcOffset || destOffset)
		{

			//TODO("make this more efficient");
			for (u64 i = 0; i < length; ++i, ++bitIdx, ++offset)
			{
				u8 bit = dataIn[offset / 8] & masks[offset % 8];
				(*this)[bitIdx] = bit;
			}
		}
		else
		{
			memcpy(data() + destIdx, dataIn + srcIdx, byteLength);
		}
	}


	void BitVector::append(const BitVector& k, u64 length, u64 offset) {
		if (k.size() < length + offset)
			throw std::runtime_error("length too long. " LOCATION);

		append(k.data(), length, offset);
	}

	void BitVector::reserve(u64 bits)
	{
		u64 curBits = mNumBits;
		resize(bits);

		mNumBits = curBits;
	}

	void BitVector::resize(u64 newSize)
	{
		u64 new_nblocks = divCeil(newSize, 8 * sizeof(block));

		if (mAllocBlocks < new_nblocks)
		{
			std::unique_ptr<block[]> tmp(new block[new_nblocks]());
			mAllocBlocks = new_nblocks;

			std::copy_n(mData.get(), sizeBlocks(), tmp.get());
			mData = std::move(tmp);
		}
		mNumBits = newSize;
	}

	void BitVector::resize(u64 newSize, u8 val)
	{

		val = bool(val) * ~0;

		auto oldSize = size();
		resize(newSize);

		u64 offset = oldSize & 7;
		u64 idx = oldSize / 8;

		if (offset)
		{
			u8 mask = (~0) << offset;
			data()[idx] = (data()[idx] & ~mask) | (val & mask);
			++idx;
		}

		u64 rem = sizeBytes() - idx;
		if (rem)
			memset(data() + idx, val, rem);
	}

	void BitVector::reset(size_t new_nbits)
	{
		u64 newSize = divCeil(new_nbits, 8 * sizeof(block));

		if (newSize > mAllocBlocks)
		{

			mData.reset(new block[newSize]());
			mAllocBlocks = newSize;
		}
		else
		{
			std::fill_n(mData.get(), newSize, block(0, 0));
		}

		mNumBits = new_nbits;
	}

	void BitVector::copy(const BitVector& src, u64 idx, u64 length)
	{
		resize(0);
		append(src.data(), length, idx);
	}


	BitVector BitVector::operator~() const
	{
		BitVector ret(*this);

		for (u64 i = 0; i < sizeBlocks(); i++)
			ret.mData[i] = ~mData[i];

		return ret;
	}


	void BitVector::operator&=(const BitVector& A)
	{
		if (mNumBits != A.mNumBits) throw std::runtime_error("rt error at " LOCATION);
		for (u64 i = 0; i < sizeBlocks(); i++)
		{
			mData[i] &= A.mData[i];
		}
	}

	void BitVector::operator|=(const BitVector& A)
	{
		if (mNumBits != A.mNumBits) throw std::runtime_error("rt error at " LOCATION);
		for (u64 i = 0; i < sizeBlocks(); i++)
		{
			mData[i] |= A.mData[i];
		}
	}

	void BitVector::operator^=(const BitVector& A)
	{
		if (mNumBits != A.mNumBits) throw std::runtime_error("rt error at " LOCATION);
		for (u64 i = 0; i < sizeBlocks(); i++)
		{
			mData[i] ^= A.mData[i];
		}
	}
	void BitVector::fromString(std::string data)
	{
		resize(data.size());

		for (u64 i = 0; i < size(); ++i)
		{
#ifndef NDEBUG
			if (u8(data[i] - '0') > 1) throw std::runtime_error("");
#endif

			(*this)[i] = data[i] - '0';
		}

	}


	bool BitVector::equals(const BitVector& rhs) const
	{

		if (mNumBits != rhs.mNumBits)
			return false;

		u64 lastByte = sizeBytes() - 1;
		if (memcmp(data(), rhs.data(), lastByte)) return false;

		// numBits = 4
		// 00001010
		// 11111010
		//     ^^^^ compare these

		u64 rem = mNumBits & 7;
		u8 mask = rem ? ((u8)-1) >> (8 - rem) : ~0;
		if ((data()[lastByte] & mask) != (rhs.data()[lastByte] & mask))
			return false;

		return true;
	}

	void BitVector::nChoosek(u64 n, u64 k, PRNG& prng)
	{
		reset(n);
		// wiki: Reservoir sampling


		memset(data(), u8(-1), k / 8);
		for (u64 i = k - 1; i >= (k & (~3)); --i)
			(*this)[i] = 1;


		for (u64 i = k; i < n; ++i)
		{
			u64 j = prng.get<u64>() % i;

			if (j < k)
			{
				u8 b = (*this)[j];
				(*this)[j] = 0;
				(*this)[i] = b;
			}
		}
	}

	u64 BitVector::hammingWeight() const
	{
		//TODO("make sure top bits are cleared");
		u64 ham(0);
		auto e = sizeBytes() - bool(size() & 7) * 1;
		for (u64 i = 0; i < e; ++i)
		{
			u8 b = data()[i];
			while (b)
			{
				++ham;
				b &= b - 1;
			}
		}

		for (u64 i = e * 8; i < size(); ++i)
		{
			ham += (*this)[i];
		}

		return ham;
	}


	u8 BitVector::parity()
	{
		return hammingWeight() & 1;
	}

	void BitVector::pushBack(u8 bit)
	{
		if (size() == capacity())
		{
			reserve(size() * 2);
		}

		resize(size() + 1);

		back() = bit;
	}
	void BitVector::randomize(PRNG& G)
	{
		G.get(mData.get(), sizeBlocks());
	}

	std::string BitVector::hex() const
	{
		std::stringstream s;

		s << std::hex;
		for (unsigned int i = 0; i < sizeBytes(); i++)
		{
			s << std::setw(2) << std::setfill('0') << int(data()[i]);
		}

		return s.str();
	}

	std::ostream& operator<<(std::ostream& out, const BitVector& vec)
	{
		//for (i64 i = static_cast<i64>(val.size()) - 1; i > -1; --i)
		//{
		//    in << (u32)val[i];
		//}

		//return in;
		for (u64 i = 0; i < vec.size(); ++i)
		{
			out << char('0' + (u8)vec[i]);
		}

		return out;
	}

}
