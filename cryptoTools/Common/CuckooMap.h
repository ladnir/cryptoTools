#pragma once

#include <cryptoTools/Common/CuckooHasher.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/AES.h>
#include <vector>
#include <memory>
#include <array>
#include <random>

#define CUCKOO_MAP_STASH_SIZE 8
#define CUCKOO_MAP_THRESHOLD 128

using std::vector;
using std::unique_ptr;

namespace osuCrypto {

template<typename V>
class CuckooMap {
public:
    CuckooMap<V>(u64 n);
    V& operator[](u64 key);

private:
    u64 n, next_bin;
    AES aes;
    unique_ptr<CuckooHasher> ch;
    vector<V> elems;
    vector<u64> keys; // for dumb lookup when n is small
};

template<typename V>
CuckooMap<V>::CuckooMap(u64 n)
    : n(n), next_bin(0), elems(n)
{
    if (n > CUCKOO_MAP_THRESHOLD) {
        ch.reset(new CuckooHasher(CUCKOO_MAP_STASH_SIZE));
        ch->init(n, 40);
        std::random_device rd;
        aes.setKey(toBlock(rd(), rd()));
    } else {
        keys.resize(n);
    }
}

template<typename V>
V&
CuckooMap<V>::operator[](u64 k)
{
    if (n > CUCKOO_MAP_THRESHOLD) {
        std::array<u64, 2> h;
        aes.ecbEncBlock(toBlock(k), (block&)h[0]);
        u64 ix = ch->find(h);
        if (ix == u64(-1)) { // not found
            ch->insert(next_bin, h);
            return elems[next_bin++];
        }
        return elems[ix];
    } else {
        u64 ix = u64(-1);
        for (u64 i = 0; i < n; i++) {
            if (k == keys[i]) {
                ix = i;
                break;
            }
        }
        if (ix == u64(-1)) {
            keys[next_bin] = k;
            return elems[next_bin++];
        }
        return elems[ix];
    }
}

} // namespace osuCrypto
