# Edwards25519 arithmetic

This directory contains the public-domain Edwards25519 arithmetic extracted
from Simplest OT. It implements the raw, cofactor-8 twisted Edwards curve over
`2^255 - 19`. The raw Edwards API is not a Ristretto or Decaf encoding.

The same arithmetic also backs the standard prime-order
`osuCrypto::Ristretto255::{Scalar, Point, Point8}` API in `Ristretto255.h`.
Ristretto encoding, canonical decoding, and the 64-byte uniform map are
performed only at that API boundary; scalar multiplication and group
operations reuse the Edwards extended-coordinate kernels without conversion.

Raw Edwards decoding accepts the full cofactor-8 curve. Protocols receiving
raw Edwards points from an untrusted peer must call `clearCofactor()` before
using them in group operations, or use the Ristretto255 facade when a
prime-order abstraction is desired. Failed scalar and batched decodes leave
the destination object unchanged.

Edwards25519 is always part of the main `cryptoTools` library. The public C++
API is `osuCrypto::Edwards25519::{Scalar, Point, Point8}` in
`Edwards25519.h`. The low-level arithmetic has a C ABI so the assembly kernels
remain replaceable without C++ name mangling or runtime dispatch.

Applications that want the best configured implementation should include
`Curve25519Backend.h` and use `osuCrypto::Edwards25519::Backend` or
`osuCrypto::Ristretto255::Backend`. Each facade exposes `Scalar`, `Point`, and
the fixed-width `Point8` batch type without runtime dispatch. Edwards25519 is
selected in the order IFMA, assembly, portable C;
Ristretto255 is selected in the order IFMA, assembly, libsodium, portable C.
The Elligator2 hash-to-curve result and both canonical encodings are identical
across providers, so builds using different providers remain wire compatible.

The external Edwards25519 providers were intentionally removed from automatic
selection: pinned-core Masny--Rindal measurements found portable C 18% faster
than libsodium and 26% faster than RELIC. Ristretto255 retains libsodium, where
it remains substantially faster than portable C.

The portable backend contains independent radix-2^51 field arithmetic and
scalar extended-coordinate curve formulas. Its `Point8` representation uses
two four-lane blocks; the portable implementation therefore runs eight scalar
points and is the correctness reference and fallback for unsupported
platforms.

Set `ENABLE_EDWARDS25519_ASM=ON` to select the optimized backend on x86-64
Linux/System-V or Windows/MSVC. Each half of `Point8` retains the original
fixed-width four-lane AVX layout and qhasm-generated kernels. Backend selection
is at compile time, so the optimized hot path has no indirect calls or runtime
feature checks.

Set `ENABLE_EDWARDS25519_IFMA=ON` to select the native eight-lane backend on
x86-64 processors with AVX-512F and AVX-512IFMA. It uses a five-limb
radix-2^52 field representation and keeps all eight points in AVX-512 vectors
through Elligator2, point arithmetic, encoding, decoding, and scalar
multiplication. The IFMA source file receives its ISA flags independently, so
enabling it does not compile the rest of cryptoTools for AVX-512. If both IFMA
and the assembly backend are enabled, scalar `Point` operations use assembly
and batched `Point8` operations use IFMA.

Backend selection is compile-time only. A binary built with the IFMA backend
must only run on a CPU that supports AVX-512F and AVX-512IFMA; cryptoTools does
not add runtime dispatch. Leave `ENABLE_EDWARDS25519_IFMA=OFF` to retain the
assembly or portable fallback.

All Edwards25519 objects are compiled as position-independent code. The
assembly constants use RIP-relative addressing, allowing the resulting
objects to be included in PIE executables and shared libraries.

The Win64 MASM source is mechanically produced by
`asm/win64/generate_win64_asm.py` from the qhasm/GAS instruction streams in
`asm/sysv`. Its generated prologues adapt
the Microsoft x64 argument registers, preserve nonvolatile integer and vector
registers, and emit unwind metadata. Regenerate the `.asm` file after changing
one of the source `.s` files.

`ifma/ge8x_ifma.cpp` is licensed under Apache-2.0 because its radix-2^52
multiplication and reduction schedule is derived from Intel Cryptography
Primitives. The file retains the Intel attribution and license notice.
The portable Ristretto formulas in `ristretto255.c` are adapted from
libsodium ref10 under the ISC license in `RISTRETTO_LICENSE`.
