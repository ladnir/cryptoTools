# Optional VAES backend

`ENABLE_VAES=ON` selects a 256-bit VAES implementation at compile time.
The option defaults to OFF and requires x86, SSE, AVX, AVX2, and compiler support
for the VAES intrinsics. It does not require AVX-512. GCC and Clang consumers
inherit `-mvaes -mavx2`; MSVC consumers inherit `/arch:AVX2`.

There is no CPU dispatch at runtime. Deploy this build only on VAES-capable
machines. Installed-package consumers can require the `vaes` or `no_vaes`
component of `find_package(cryptoTools ...)`.

The implementation preserves the AES API and expanded-key layout. It processes
up to sixteen blocks with eight independent YMM states. Smaller batches use
fewer states; larger batches repeat the sixteen-block kernel. An odd final block
uses AES-NI. Encryption and Davies–Meyer hashing support exact in-place operation
and the existing 16-byte alignment. Key expansion and decryption are unchanged.

## Measured throughput

Ryzen 9 7950X, one core fixed at 4.5 GHz, boost disabled, GCC 13.4, Release,
AVX2 enabled and AVX-512 disabled. Runs are serialized. The kernel benchmark
reports the median of seven trials and counts sixteen payload bytes per AES block.
Reported GB/s is payload throughput, not total read-plus-write memory traffic.

| Kernel, 16 KiB working buffer | AES-NI GB/s | VAES GB/s |
|---|---:|---:|
| ECB, fixed batch of 8 | 13.27 | 27.58 |
| ECB, fixed batch of 16 | 14.00 | 27.52 |
| Hash, fixed batch of 8 | 14.00 | 26.77 |
| Hash, fixed batch of 16 | 12.94 | 27.77 |
| ECB, runtime-sized call | 13.12 | 27.73 |
| Hash, runtime-sized call | 13.96 | 26.62 |

A separate loop executes ten VAES rounds per block with one invariant key.
It omits key-schedule loads, initial whitening, and hash feed-forward; it is not
an encryption implementation. That loop reaches 27.97 GB/s on the same buffer.
The real kernels therefore reach about 95–99% of this **empirical compute ceiling**.
This is not a claim about every CPU's architectural peak.

With a 64 MiB buffer, fixed-sixteen ECB and hashing reach 25.37 and 25.07 GB/s.
The round-only loop reaches 25.46 GB/s. A read/XOR/write pass reaches 31.93 GB/s
of payload, so the AES kernels are not at the measured memory-pass ceiling.
Disassembly confirms YMM `vaesenc`/`vaesenclast` without spills or calls in the
fixed-sixteen hash kernel. `perf` attributes the measured
work to the AES loops rather than an unexpected helper or allocator.

The full stationary-SPIN sender at K=2^18 improves from 3.770 to 3.571 ms in the
final matched three-process comparison: 69.54 to 73.41 million OTs/s. Final hashing
improves from 0.677 to 0.440 ms. This includes a VAES-aware packing change in
libOTe; merely changing AES instructions initially regressed that caller.
Two narrow stores followed by a wide load caused costly store forwarding.
libOTe now packs complete 32-byte pairs and hashes sixteen blocks together.

Fresh-leaf generation improves only from 0.989 to 0.949 ms. Its surrounding
conversion, accumulation, and memory accesses still need separate profiling.
The isolated AES speedup does not imply a twofold whole-protocol speedup.

## Reproduce

Configure separate OFF and ON build directories with otherwise identical flags.
Build the opt-in target `cryptotools_aes_bench` in each directory. The executable
is not part of normal builds or timed CTest runs.

```sh
cmake --build BUILD --target cryptotools_aes_bench
BUILD/cryptotools_aes_bench --check
bash benchmarks/run_aes_bench.sh OFF_EXE ON_EXE RESULTS_DIR 15
```

For a cryptoTools subdirectory build, the executable is usually under
`BUILD/cryptoTools/`. On Windows, use the selected configuration subdirectory.
`--check` runs correctness tests without timing. Tests cover the NIST AES vector,
fixed batch sizes 1–32, runtime sizes 0–257, in-place operation, 16-byte-offset
buffers, output guards, counter mode, and tweakable hashing.
The VAES tests passed with GCC 13.4 and MSVC 19.50. A separate GCC build passed
ASan and UBSan with portable AES enabled, exercising both implementations.

The runner takes the shared benchmark locks and runs the two executables in
alternation, never concurrently. Use a fixed-frequency core and keep other work
off that host during measurement. Raw outputs are written only to the requested
results directory; they are not source artifacts.
