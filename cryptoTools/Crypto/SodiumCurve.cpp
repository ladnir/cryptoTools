#include "SodiumCurve.h"

#ifdef ENABLE_SODIUM

namespace osuCrypto
{
namespace Sodium
{

bool Scalar25519::operator==(const Scalar25519& cmp) const
{
    return sodium_memcmp(data, cmp.data, size) == 0;
}

bool Scalar25519::iszero() const
{
    return sodium_is_zero(data, size);
}

Prime25519::Prime25519(const Scalar25519& a)
{
    crypto_core_ed25519_scalar_reduce(data, a.data);
}

Prime25519 Prime25519::inverse() const
{
    Prime25519 recip;
    crypto_core_ed25519_scalar_invert(recip.data, data);
    return recip;
}

Prime25519 operator-(const Prime25519& a)
{
    Prime25519 neg;
    crypto_core_ed25519_scalar_negate(neg.data, a.data);
    return neg;
}

Prime25519 operator+(const Prime25519& a, const Prime25519& b)
{
    Prime25519 sum;
    crypto_core_ed25519_scalar_add(sum.data, a.data, b.data);
    return sum;
}

Prime25519 operator-(const Prime25519& a, const Prime25519& b)
{
    Prime25519 diff;
    crypto_core_ed25519_scalar_sub(diff.data, a.data, b.data);
    return diff;
}

Prime25519 operator*(const Prime25519& a, const Prime25519& b)
{
    Prime25519 prod;
    crypto_core_ed25519_scalar_mul(prod.data, a.data, b.data);
    return prod;
}

bool Ed25519::operator==(const Ed25519& cmp) const
{
    return sodium_memcmp(data, cmp.data, size) == 0;
}

Ed25519 Ed25519::operator+(const Ed25519& b) const
{
    Ed25519 sum;
    crypto_core_ed25519_add(sum.data, data, b.data);
    return sum;
}

Ed25519 Ed25519::operator-(const Ed25519& b) const
{
    Ed25519 diff;
    crypto_core_ed25519_sub(diff.data, data, b.data);
    return diff;
}

Ed25519 operator*(const Prime25519& a, const Ed25519& b)
{
    Ed25519 prod;
    if (crypto_scalarmult_ed25519_noclamp(prod.data, a.data, b.data) < 0)
        throw std::runtime_error(LOCATION);
    return prod;
}

Ed25519 Ed25519::mulGenerator(const Prime25519& n)
{
    Ed25519 prod;
    if (crypto_scalarmult_ed25519_base_noclamp(prod.data, n.data) < 0)
        throw std::runtime_error(LOCATION);
    return prod;
}

bool Rist25519::operator==(const Rist25519& cmp) const
{
    return sodium_memcmp(data, cmp.data, size) == 0;
}

Rist25519 Rist25519::operator+(const Rist25519& b) const
{
    Rist25519 sum;
    crypto_core_ristretto255_add(sum.data, data, b.data);
    return sum;
}

Rist25519 Rist25519::operator-(const Rist25519& b) const
{
    Rist25519 diff;
    crypto_core_ristretto255_sub(diff.data, data, b.data);
    return diff;
}

Rist25519 operator*(const Prime25519& a, const Rist25519& b)
{
    Rist25519 prod;
    if (crypto_scalarmult_ristretto255(prod.data, a.data, b.data) < 0)
        throw std::runtime_error(LOCATION);
    return prod;
}

Rist25519 Rist25519::mulGenerator(const Prime25519& n)
{
    Rist25519 prod;
    if (crypto_scalarmult_ristretto255_base(prod.data, n.data) < 0)
        throw std::runtime_error(LOCATION);
    return prod;
}

Rist25519 Rist25519::fromHash(const unsigned char* d)
{
    Rist25519 out;
    crypto_core_ristretto255_from_hash(out.data, d);
    return out;
}

#ifdef SODIUM_MONTGOMERY

bool Monty25519::operator==(const Monty25519& cmp) const
{
    return sodium_memcmp(data, cmp.data, size) == 0;
}

Monty25519 operator*(const Scalar25519& a, const Monty25519& b)
{
    Monty25519 prod;
    if (crypto_scalarmult_noclamp(prod.data, a.data, b.data) < 0)
        throw std::runtime_error(LOCATION);
    return prod;
}

Monty25519 Monty25519::mulGenerator(const Scalar25519& n)
{
    Monty25519 prod;
    if (crypto_scalarmult_base_noclamp(prod.data, n.data) < 0)
        throw std::runtime_error(LOCATION);
    return prod;
}

const Monty25519 Monty25519::primeSubgroupGenerator{9};
const Monty25519 Monty25519::primeTwistSubgroupGenerator{2};
const Monty25519 Monty25519::wholeGroupGenerator{6};
const Monty25519 Monty25519::wholeTwistGroupGenerator{3};

#endif

}
}

#endif
