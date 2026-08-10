# Montgomery25519

This directory implements raw Montgomery `u`-coordinate arithmetic for
Curve25519 and its quadratic twist. It is not the X25519 protocol API:
scalars are not clamped, arbitrary `u` coordinates are accepted, and bit 255
of scalar and point encodings is ignored.

The behavior follows `crypto_scalarmult_noclamp()` from the modified
osu-crypto/libsodium fork. Backend selection is compile-time:

1. eight-lane AVX-512 IFMA;
2. modified libsodium when `SODIUM_MONTGOMERY` is enabled;
3. portable radix-2^51 C.

The portable and IFMA implementations are differentially tested against the
modified libsodium behavior, including its known vectors and small-order
input rejection.

The Montgomery ladder and small-order blocklist are derived from libsodium
under the ISC license in `LICENSE`. The reused cryptoTools field arithmetic
is public domain under the Edwards25519 backend's license.
