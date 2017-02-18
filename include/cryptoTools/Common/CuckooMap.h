#pragma once

#include <cryptoTools/Common/CuckooHasher.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/AES.h>
#include <vector>
#include <memory>
#include <random>

#define CUCKOO_MAP_STASH_SIZE 3

using std::vector;
using std::unique_ptr;

namespace osuCrypto {

block dev_random_seed();

template<typename V>
class CuckooMap {
public:
    CuckooMap<V>(u64 n);
    V& operator[](u64 key);

private:
    u64 n, next_bin;
    AES aes;
    CuckooHasher ch;
    vector<V> elems;
};

template<typename V>
CuckooMap<V>::CuckooMap(u64 n)
    : n(n), next_bin(0), ch(CUCKOO_MAP_STASH_SIZE), elems(n)
{
    ch.init(n, 40);
    std::random_device rd;
    aes.setKey(toBlock(rd(), rd()));
}

template<typename V>
V&
CuckooMap<V>::operator[](u64 key)
{
    auto h = ArrayView<u64>(2);
    aes.ecbEncBlock(toBlock(key), (block&)h[0]);
    u64 ix = ch.find(h);
    if (ix == u64(-1)) { // not found
        ch.insert(next_bin, h);
        return elems[next_bin++];
    } else {
        return elems[ix];
    }
}

} // namespace osuCrypto
