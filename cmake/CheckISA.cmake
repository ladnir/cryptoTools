include(CheckCXXCompilerFlag)
include(CheckCXXSourceRuns)

# Helper to test: compiler accepts flag AND the produced binary actually runs.
function(check_isa_runs ISA_NAME ISA_FLAG TEST_SRC OUT_VAR)
  set(${OUT_VAR} FALSE PARENT_SCOPE)

  # 1) Does the compiler accept the flag?
  
  #if("${ISA_FLAG}" STREQUAL "")
  #  # No flag to test, assume true (e.g. BMI2 on MSVC)
  #  message(STATUS " ${ISA_NAME}: no special compiler flag to #test")
  #  set(HAVE_FLAG TRUE)
  #else()
  #  message(STATUS " ${ISA_NAME}: testing compiler flag: #${ISA_FLAG}")
  #  check_cxx_compiler_flag(${ISA_FLAG} HAVE_FLAG)
  #endif()
  #
  #if (NOT HAVE_FLAG)
  #  message(STATUS " ${ISA_NAME}: compiler does not accept #flag: ${ISA_FLAG}")
  #  return()
  #endif()

  # 2) On cross builds we can’t run the test — be conservative
  if (CMAKE_CROSSCOMPILING)
    message(STATUS "${ISA_NAME}: cross-compiling; skipping run test -> FALSE")
    return()
  endif()

  # 3) Unique cache key per (ISA, flag, source)
  string(MD5 _hash "${TEST_SRC}||${ISA_FLAG}")
  set(_KEY "RUN_${ISA_NAME}_${_hash}")

  # Ensure a fresh check whenever source/flag changes
  #unset(${_KEY} CACHE)

  # Pass the ISA flag to the try_run compile
  set(_SAVE_REQ_FLAGS "${CMAKE_REQUIRED_FLAGS}")
  set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} ${ISA_FLAG}")

  # Optional: see compiler errors from try_compile/try_run
  set(CMAKE_REQUIRED_QUIET TRUE)


  check_cxx_source_runs("${TEST_SRC}" ${_KEY})

  #message(STATUS "${CMAKE_REQUIRED_FLAGS}\n\n${TEST_SRC}")

  set(CMAKE_REQUIRED_FLAGS "${_SAVE_REQ_FLAGS}")

  set(${OUT_VAR} ${${_KEY}} PARENT_SCOPE)
  if(${${_KEY}})
    set(RESULT TRUE)
  else()
    set(RESULT FALSE)
  endif()
  message(STATUS "${ISA_NAME}: runtime support ${RESULT} (flag=${ISA_FLAG})")
endfunction()

# ---- Test sources (each *executes* a distinctive intrinsic) ----
set(TEST_SSE2 "
  #include <emmintrin.h>
  int main(){
    __m128i a = _mm_set1_epi32(1), b = _mm_set1_epi32(2);
    __m128i c = _mm_add_epi32(a,b);
    volatile int v = _mm_cvtsi128_si32(c);
    (void)v; return 0;
  }")

set(TEST_AVX "
  #include <immintrin.h>
  int main(){
    __m256 a = _mm256_set1_ps(1.0f), b = _mm256_set1_ps(2.0f);
    __m256 c = _mm256_add_ps(a,b);
    volatile float v = ((float*)&c)[0];
    (void)v; return 0;
  }")

set(TEST_AVX2 "
  #include <immintrin.h>
  int main(){
    __m256i a = _mm256_set1_epi32(3), b = _mm256_set1_epi32(4);
    __m256i c = _mm256_mullo_epi32(a,b); // AVX2-specific integer op
    volatile int v = ((int*)&c)[0];
    (void)v; return 0;
  }")

set(TEST_AVX512 [[
  #include <immintrin.h>
  int main(){
    alignas(64) int d[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    volatile int u = d[0];
    __m512i X = _mm512_loadu_si512((const void*)d);
    __m512i Y = _mm512_add_epi32(X, _mm512_set1_epi32(u));
    _mm512_storeu_si512((void*)d, Y);
    return d[0]==0;
  }]])

  set(TEST_BMI2 [[
      #include <immintrin.h> 
      #include <cstdlib>
      int main(){ 
        long long unsigned int x = 0b1100;
        volatile unsigned long long y = _mulx_u64(rand(), rand(), &x); 
        (void)y; return y==0b10;
    }]])

# ---- Run the checks (MSVC flags; add GCC/Clang alternates if you use them) ----
if (MSVC)
  set(FLAG_SSE2   "/arch:SSE2")   # default on x64 but the test is harmless
  set(FLAG_AVX    "/arch:AVX")
  set(FLAG_AVX2   "/arch:AVX2")
  set(FLAG_AVX512 "/arch:AVX512")
  set(FLAG_BMI2    "/arch:AVX2") # no /arch flag for BMI2
else()
  # clang/gcc (helps when using clang-cl or mingw)
  set(FLAG_SSE2   "-msse2")
  set(FLAG_AVX    "-mavx")
  set(FLAG_AVX2   "-mavx2")
  set(FLAG_AVX512 "-mavx512f")
  set(FLAG_BMI2   "-mbmi2")
endif()

check_isa_runs("SSE2"   "${FLAG_SSE2}"   "${TEST_SSE2}"   SSE2_RUNS)
check_isa_runs("AVX"    "${FLAG_AVX}"    "${TEST_AVX}"    AVX_RUNS)
check_isa_runs("AVX2"   "${FLAG_AVX2}"   "${TEST_AVX2}"   AVX2_RUNS)
check_isa_runs("AVX512" "${FLAG_AVX512}" "${TEST_AVX512}" AVX512_RUNS)
check_isa_runs("BMI2"   "${FLAG_BMI2}"   "${TEST_BMI2}"   BMI2_RUNS)


# Expose as cache options so users can override if they *really* want.
set(ENABLE_SSE_DEFAULT   ${SSE2_RUNS}   CACHE BOOL "Enable SSE2 codepaths by default")
set(ENABLE_AVX_DEFAULT    ${AVX_RUNS}    CACHE BOOL "Enable AVX codepaths by default")
set(ENABLE_AVX2_DEFAULT   ${AVX2_RUNS}   CACHE BOOL "Enable AVX2 codepaths by default")
set(ENABLE_AVX512_DEFAULT ${AVX512_RUNS} CACHE BOOL "Enable AVX-512 codepaths by default")
set(ENABLE_BMI2_DEFAULT ${AVX512_RUNS} CACHE BOOL "Enable AVX-512 codepaths by default")
