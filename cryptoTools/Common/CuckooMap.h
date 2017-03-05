#pragma once

#include <cryptoTools/Common/CuckooHasher.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/AES.h>
#include <vector>
#include <memory>
#include <array>
#include <random>
#include <boost/optional.hpp>
#include <boost/variant.hpp>

#define CUCKOO_MAP_THRESHOLD 256

//using std::vector;
//using std::unique_ptr;

namespace osuCrypto {

    template<typename T>
    using Optional = boost::optional<T>;

    template<typename T, typename V>
    using Enable_If_Small_POD = typename std::enable_if<std::is_pod<T>::value && (sizeof(T) <= 16), V>::type;

    template<typename T>
    Enable_If_Small_POD<T, block> cuckooHashFunction(const T& data)
    {
        block temp = ZeroBlock;
        memcpy(&temp, &data, sizeof(T));

        // two rounds of fixed key AES should be sufficient in a non security concerned setting.
        return _mm_aesenc_si128(_mm_aesenc_si128(temp, mAesFixedKey.mRoundKey[1]), mAesFixedKey.mRoundKey[2]) ^ temp;

        //return mAesFixedKey.ecbEncBlock(temp) ^ temp;
    }

    namespace details
    {


        template<typename key_type, typename value_type>
        class CuckooMapBase
        {
        public:
            virtual void init(u64 n) = 0;

            virtual value_type& operator[](const key_type& key) = 0;

            virtual void insert(const key_type& key, const value_type& value) = 0;
            virtual void insert(ArrayView<key_type> keys, ArrayView<value_type> values) = 0;

            virtual Optional<value_type&> find(const key_type& key) = 0;
            virtual void find(ArrayView<key_type> keys, ArrayView<Optional<value_type&>> values) = 0;
        };


        template<typename key_type, typename value_type>
        class SmallCuckooMap : public CuckooMapBase<key_type, value_type>
        {
        public:


            // place them together to save on the number of pointer/size variables.
            std::vector<std::pair<key_type, value_type>> mKeyValues;
            u64 mNextFree;

            SmallCuckooMap() = default;
            ~SmallCuckooMap() = default;

            SmallCuckooMap(u64 n)
            {
                init(n);
            }

            void init(u64 n)
            {
                mKeyValues.resize(n);
                mNextFree = (0);
            }

            value_type& operator[](const key_type& key)
            {
                auto v = find(key);
                if (v) {
                    return *v;
                }
                else {
                    mKeyValues[mNextFree].first = key;
                    return mKeyValues[mNextFree++].second;
                }
            }

            void insert(const key_type& key, const value_type& value) {
                mKeyValues[mNextFree].first = key;
                mKeyValues[mNextFree++].second = value;
            }

            void insert(ArrayView<key_type> keys, ArrayView<value_type> values) {
                for (u64 i = 0; i < keys.size(); ++i) {
                    insert(keys[i], values[i]);
                }
            }

            Optional<value_type&> find(const key_type& key) {
                for (u64 i = 0; i < mNextFree; ++i) {
                    if (key == mKeyValues[i].first) {
                        return Optional<value_type&>{mKeyValues[i].second};
                    }
                }

                return Optional<value_type&>{};
            }


            void find(ArrayView<key_type> keys, ArrayView<Optional<value_type&>> values) {
                for (u64 i = 0; i < keys.size(); ++i) {
                    values[i] = find(keys[i]);
                }
            }

        };

        template<typename key_type, typename value_type>
        class BigCuckooMap : public CuckooMapBase<key_type, value_type>
        {
        public:
            static_assert(std::is_pod<key_type>::value && sizeof(key_type) < 16, "key_type must be pod and no larger than 16 bytes");

            CuckooHasher mImpl;
            std::vector<value_type> mValues;
            u64 mNextBin;

            BigCuckooMap() = default;
            ~BigCuckooMap() = default;
            BigCuckooMap(u64 n)
            {
                init(n);
            }

            void init(u64 n)
            {
                mValues.resize(n);
                mNextBin = (0);
                mImpl.init(n, 0);
            }


            value_type& operator[](const key_type& key)
            {
                auto k = cuckooHashFunction(key);

                auto index = mImpl.find(k);

                if (index == u64(-1))
                {
                    mImpl.insert(mNextBin, k);

                    return mValues[mNextBin++];
                }
                else
                {
                    return mValues[index];
                }
            }


            void insert(const key_type& key, const value_type& value)
            {
                auto k = cuckooHashFunction(key);

                mValues[mNextBin] = value;
                mImpl.insert(mNextBin++, k);
            }

            void insert(ArrayView<key_type> keys, ArrayView<value_type> values)
            {
                std::vector<u64> indexes(values.size());
                std::vector<block> hashes(values.size());

                for (u64 i = 0; i < values.size(); ++i)
                {
                    indexes[i] = mNextBin;
                    hashes[i] = cuckooHashFunction(keys[i]);

                    mValues[mNextBin++] = values[i];
                }

                mImpl.insert(values.size(), indexes.data(), hashes.data());
            }

            Optional<value_type&> find(const key_type& key)
            {
                auto k = cuckooHashFunction(key);
                auto idx = mImpl.find(k);

                if (idx == u64(-1))
                {
                    return Optional<value_type&>{};
                }
                else
                {
                    return Optional<value_type&>(mValues[idx]);
                }
            }


            void find(ArrayView<key_type> keys, ArrayView<Optional<value_type&>> values)
            {
                std::vector<u64> indexes(values.size());
                std::vector<block> hashes(values.size());

                for (u64 i = 0; i < values.size(); ++i)
                {
                    hashes[i] = cuckooHashFunction(keys[i]);
                }

                mImpl.find(hashes.size(), hashes.data(), indexes.data());

                for (u64 i = 0; i < values.size(); ++i)
                {
                    if (indexes[i] == u64(-1))
                    {
                        values[i] = Optional<value_type&>{};
                    }
                    else
                    {
                        values[i] = Optional<value_type&>(mValues[indexes[i]]);
                    }
                }
            }
        };
    }


    template<typename key_type, typename value_type>
    class CuckooMap2
    {
    public:

        std::unique_ptr<details::CuckooMapBase<key_type, value_type>> mImpl;

        CuckooMap2() {};
        CuckooMap2(u64 n) { init(n); }


        void init(u64 n)
        {
            if (n < CUCKOO_MAP_THRESHOLD)
            {
                mImpl.reset(new details::SmallCuckooMap<key_type, value_type>(n));
            }
            else
            {
                mImpl.reset(new details::BigCuckooMap<key_type, value_type>(n));
            }
        }

        value_type& operator[](const key_type& key)
        {
            return (*mImpl)[key];
        }


        void insert(const key_type& key, const value_type& value)
        {
            mImpl->insert(key, value);
        }

        void insert(ArrayView<key_type> keys, ArrayView<value_type> values)
        {
            mImpl->insert(keys, values);
        }

        Optional<value_type&> find(const key_type& key)
        {
            return mImpl->find(key);
        }

        void find(ArrayView<key_type> keys, ArrayView<Optional<value_type&>> values)
        {
            mImpl->find(keys, values);
        }

    };




    template<typename value_type>
    class CuckooMap
    {
    public:
        CuckooMap(u64 n);
        value_type& operator[](u64 key);

    private:
        u64 mN, mNextBin;
        AES mAes;
        std::unique_ptr<CuckooHasher> mCH;
        std::vector<value_type> mElems;
        std::vector<u64> mKeys; // for dumb lookup when n is small
    };

    template<typename value_type>
    CuckooMap<value_type>::CuckooMap(u64 n)
        : mN(n), mNextBin(0), mElems(n)
    {
        if (n > CUCKOO_MAP_THRESHOLD) {
            mCH.reset(new CuckooHasher());
            mCH->init(n, 40);
            std::random_device rd;
            mAes.setKey(toBlock(rd(), rd()));
        }
        else {
            mKeys.resize(n);
        }
    }

    template<typename value_type>
    value_type& CuckooMap<value_type>::operator[](u64 k)
    {
        if (mN > CUCKOO_MAP_THRESHOLD) {
            block h = mAes.ecbEncBlock(toBlock(k));
            u64 ix = mCH->find(h);
            if (ix == u64(-1)) { // not found
                mCH->insert(mNextBin, h);
                return mElems[mNextBin++];
            }
            return mElems[ix];
        }
        else {
            u64 ix = u64(-1);
            for (u64 i = 0; i < mNextBin; i++) {
                if (k == mKeys[i]) {
                    ix = i;
                    break;
                }
            }
            if (ix == u64(-1)) {
                mKeys[mNextBin] = k;
                return mElems[mNextBin++];
            }
            return mElems[ix];
        }
    }


} // namespace osuCrypto
