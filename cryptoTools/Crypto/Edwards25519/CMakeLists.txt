# Public-domain Edwards25519 arithmetic originally distributed with
# Simplest OT. The object library is an implementation detail: its objects are
# folded into the main cryptoTools archive below.

set(EDWARDS25519_COMMON_SOURCES
    Edwards25519.cpp
    Ristretto255.cpp
    portable/fe25519_add.c
    portable/fe25519_getparity.c
    portable/fe25519_invert.c
    portable/fe25519_iseq_vartime.c
    portable/fe25519_neg.c
    portable/fe25519_pack.c
    portable/fe25519_pow2523.c
    portable/fe25519_setint.c
    portable/fe25519_sub.c
    portable/fe25519_unpack.c
    portable/fe25519_utils.c
    portable/ge25519_add.c
    portable/ge25519_double.c
    portable/ge25519_elligator2.c
    portable/ge25519_pack.c
    portable/ge25519_scalarmult.c
    portable/ge25519_scalarmult_base.c
    portable/ge25519_setneutral.c
    portable/ge25519_unpack.c
    portable/ge25519_utils.c
    portable/ristretto255.c
    portable/sc25519_from32bytes.c
    portable/sc25519_to32bytes.c
    portable/sc25519_window4.c)

set(EDWARDS25519_SYSV_ASM_SOURCES
    asm/sysv/consts.s
    asm/sysv/consts4x.s
    asm/sysv/fe25519_freeze.s
    asm/sysv/fe25519_mul.s
    asm/sysv/fe25519_nsquare.s
    asm/sysv/fe25519_square.s
    asm/sysv/ge25519_add_p1p1.s
    asm/sysv/ge25519_dbl_p1p1.s
    asm/sysv/ge25519_lookup.s
    asm/sysv/ge25519_lookup_niels.s
    asm/sysv/ge25519_nielsadd2.s
    asm/sysv/ge25519_p1p1_to_p2.s
    asm/sysv/ge25519_p1p1_to_p3.s
    asm/sysv/ge4x_add_p1p1.s
    asm/sysv/ge4x_double_p1p1.s
    asm/sysv/ge4x_lookup.s
    asm/sysv/ge4x_lookup_niels.s
    asm/sysv/ge4x_niels_add_p1p1.s
    asm/sysv/gfe4x_add.s
    asm/sysv/gfe4x_mul.s
    asm/sysv/gfe4x_square.s
    asm/sysv/gfe4x_sub.s)

set(EDWARDS25519_WIN64_ASM_SOURCES
    asm/win64/edwards25519_win64.asm)

set(EDWARDS25519_ASM_SUPPORT_SOURCES
    batch/ge4x.c
    batch/ge4x_elligator2.cpp
    batch/ge4x_pack.c
    batch/ge4x_unpack_vartime.c
    batch/gfe4x.c
    batch/gfe4x_getparity.c
    batch/gfe4x_iseq_vartime.c
    batch/gfe4x_nsquare.c
    batch/gfe4x_pow2523.c)

set(EDWARDS25519_REF_SOURCES
    portable/fe25519_ref.c
    portable/ge25519_ref.c
    batch/ge4x_ref.c
    batch/ge4x_elligator2_ref.c)

if(ENABLE_EDWARDS25519_ASM)
    if(MSVC)
        enable_language(ASM_MASM)
        set(EDWARDS25519_BACKEND_SOURCES
            ${EDWARDS25519_WIN64_ASM_SOURCES}
            ${EDWARDS25519_ASM_SUPPORT_SOURCES})
    else()
        enable_language(ASM)
        set(EDWARDS25519_BACKEND_SOURCES
            ${EDWARDS25519_SYSV_ASM_SOURCES}
            ${EDWARDS25519_ASM_SUPPORT_SOURCES})
    endif()
else()
    set(EDWARDS25519_BACKEND_SOURCES ${EDWARDS25519_REF_SOURCES})
endif()

add_library(cryptoToolsEdwards25519Objects OBJECT
    ${EDWARDS25519_COMMON_SOURCES}
    ${EDWARDS25519_BACKEND_SOURCES})

if(ENABLE_EDWARDS25519_IFMA)
    target_sources(cryptoToolsEdwards25519Objects PRIVATE ifma/ge8x_ifma.cpp)
    if(MSVC)
        set_source_files_properties(ifma/ge8x_ifma.cpp PROPERTIES
            COMPILE_OPTIONS "/arch:AVX512")
    else()
        set_source_files_properties(ifma/ge8x_ifma.cpp PROPERTIES
            COMPILE_OPTIONS "-mavx512f;-mavx512ifma")
    endif()
endif()

# Select the public curve facades at compile time. Edwards25519 always uses
# cryptoTools' implementation; libsodium remains the optimized Ristretto255
# fallback when neither native backend is enabled.
if(NOT ENABLE_EDWARDS25519_IFMA AND NOT ENABLE_EDWARDS25519_ASM)
    if(ENABLE_SODIUM)
        target_compile_definitions(cryptoTools PUBLIC
            CRYPTOTOOLS_RISTRETTO255_BACKEND_SODIUM=1)
    endif()
endif()

set_target_properties(cryptoToolsEdwards25519Objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

target_include_directories(cryptoToolsEdwards25519Objects PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../..
    ${CMAKE_CURRENT_BINARY_DIR}/../../..
    ${CMAKE_CURRENT_SOURCE_DIR}/portable
    ${CMAKE_CURRENT_SOURCE_DIR}/batch
    ${CMAKE_CURRENT_SOURCE_DIR}/ifma)

if(MSVC)
    target_compile_options(cryptoToolsEdwards25519Objects PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:/std:c++${CRYPTO_TOOLS_STD_VER}>)
else()
    target_compile_options(cryptoToolsEdwards25519Objects PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:-std=c++${CRYPTO_TOOLS_STD_VER}>)
endif()

# Edwards25519.cpp now uses cryptoTools' hashing interface, whose configured
# implementation may require the same public ISA flags as the parent target.
target_compile_options(cryptoToolsEdwards25519Objects PRIVATE
    $<TARGET_PROPERTY:cryptoTools,INTERFACE_COMPILE_OPTIONS>)
target_compile_definitions(cryptoToolsEdwards25519Objects PRIVATE
    $<TARGET_PROPERTY:cryptoTools,INTERFACE_COMPILE_DEFINITIONS>)

if(ENABLE_EDWARDS25519_ASM)
    target_compile_definitions(cryptoToolsEdwards25519Objects PRIVATE
        CRYPTOTOOLS_EDWARDS25519_ASM=1)
    target_compile_definitions(cryptoTools PUBLIC
        CRYPTOTOOLS_EDWARDS25519_ASM=1)
    if(NOT MSVC)
        target_compile_options(cryptoToolsEdwards25519Objects PRIVATE
            $<$<COMPILE_LANGUAGE:ASM>:-Wa,--noexecstack>)
    endif()
endif()

if(ENABLE_EDWARDS25519_IFMA)
    target_compile_definitions(cryptoToolsEdwards25519Objects PRIVATE
        CRYPTOTOOLS_EDWARDS25519_IFMA=1)
    target_compile_definitions(cryptoTools PUBLIC
        CRYPTOTOOLS_EDWARDS25519_IFMA=1)
endif()

target_sources(cryptoTools PRIVATE
    $<TARGET_OBJECTS:cryptoToolsEdwards25519Objects>)
