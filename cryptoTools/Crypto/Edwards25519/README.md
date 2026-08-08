# Edwards25519 arithmetic

This directory contains the public-domain Edwards25519 arithmetic extracted
from Simplest OT. It implements the raw, cofactor-8 twisted Edwards curve over
`2^255 - 19`. It is not a Ristretto or Decaf encoding.

Edwards25519 is always part of the main `cryptoTools` library. The public C++
API is `osuCrypto::Edwards25519::{Scalar, Point, Point8}` in
`Edwards25519.h`. The low-level arithmetic has a C ABI so the assembly kernels
remain replaceable without C++ name mangling or runtime dispatch.

The portable backend contains independent radix-2^51 field arithmetic and
scalar extended-coordinate curve formulas. `Point8` currently contains two
four-lane blocks; the portable implementation therefore runs eight scalar
points and is the correctness reference and fallback for unsupported
platforms.

Set `ENABLE_EDWARDS25519_ASM=ON` to select the optimized backend on x86-64
Linux/System-V or Windows/MSVC. Each half of `Point8` retains the original
fixed-width four-lane AVX layout and qhasm-generated kernels. Backend selection
is at compile time, so the optimized hot path has no indirect calls or runtime
feature checks.

All Edwards25519 objects are compiled as position-independent code. The
assembly constants use RIP-relative addressing, allowing the resulting
objects to be included in PIE executables and shared libraries.

The Win64 MASM source is mechanically produced by `generate_win64_asm.py`
from those same qhasm/GAS instruction streams. Its generated prologues adapt
the Microsoft x64 argument registers, preserve nonvolatile integer and vector
registers, and emit unwind metadata. Regenerate the `.asm` file after changing
one of the source `.s` files.
