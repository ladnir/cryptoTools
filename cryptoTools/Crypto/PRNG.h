#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use. 
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/AES.h>
#include <cryptoTools/Crypto/sha1.h>
#include <vector>

#define SEED_SIZE   AES_BLK_SIZE
#define RAND_SIZE   AES_BLK_SIZE


namespace osuCrypto
{

    class PRNG
    {
    public:

        block mSeed;
        std::vector<block> mBuffer, mIndexArray;
        AES mAes;
        u64 mBytesIdx, mBlockIdx, mBufferByteCapacity;
        void refillBuffer();



        PRNG();
        PRNG(const block& seed);
        PRNG(const PRNG&) = delete;
        PRNG(PRNG&& s);


        // Set seed from array
        void SetSeed(const block& b);
        const block getSeed() const;


        template<typename T>
        T get()
        {
            static_assert(std::is_pod<T>::value, "T must be POD");
            T ret;
            get((u8*)&ret, sizeof(T));
            return ret;
        }



        template<typename T>
        void get(T* dest, u64 length)
        {
            static_assert(std::is_pod<T>::value, "T must be POD");
            u64 lengthu8 = length * sizeof(T);
            u8* destu8 = (u8*)dest;
            while (lengthu8)
            {
                u64 step = std::min(lengthu8, mBufferByteCapacity - mBytesIdx);

                memcpy(destu8, ((u8*)mBuffer.data()) + mBytesIdx, step);

                destu8 += step;
                lengthu8 -= step;
                mBytesIdx += step;

                if (mBytesIdx == mBufferByteCapacity)
                    refillBuffer();
            }
        }

        u8 getBit();// { return get<bool>(); }
        //void get(u8* ans, u64 len);




        typedef u32 result_type;
        static result_type min() { return 0; }
        static result_type max() { return (result_type)-1; }
        result_type operator()() {
            return get<result_type>();
        }
        result_type operator()(int mod) {
            return get<result_type>() % mod;
        }
    };

    template<>
    inline void PRNG::get<bool>(bool* dest, u64 length)
    {
        get((u8*)dest, length);
        for (u64 i = 0; i < length; ++i) dest[i] = ((u8*)dest)[i] & 1;
    }

    template<>
    inline bool PRNG::get<bool>()
    {
        u8 ret;
        get((u8*)&ret, 1);
        return ret & 1;
    }


}
