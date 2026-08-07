# Public-domain Edwards25519 arithmetic originally distributed with
# Simplest OT. The object library is an implementation detail: its objects are
# folded into the main cryptoTools archive below.

set(EDWARDS25519_COMMON_SOURCES
    Edwards25519.cpp
    fe25519_add.c
    fe25519_getparity.c
    fe25519_invert.c
    fe25519_iseq_vartime.c
    fe25519_neg.c
    fe25519_pack.c
    fe25519_pow2523.c
    fe25519_setint.c
    fe25519_sub.c
    fe25519_unpack.c
    fe25519_utils.c
    ge25519_add.c
    ge25519_double.c
    ge25519_elligator2.c
    ge25519_pack.c
    ge25519_scalarmult.c
    ge25519_scalarmult_base.c
    ge25519_setneutral.c
    ge25519_unpack.c
    ge25519_utils.c
    sc25519_from32bytes.c
    sc25519_to32bytes.c
    sc25519_window4.c)

set(EDWARDS25519_SYSV_ASM_SOURCES
    consts.s
    consts4x.s
    fe25519_freeze.s
    fe25519_mul.s
    fe25519_nsquare.s
    fe25519_square.s
    ge25519_add_p1p1.s
    ge25519_dbl_p1p1.s
    ge25519_lookup.s
    ge25519_lookup_niels.s
    ge25519_nielsadd2.s
    ge25519_p1p1_to_p2.s
    ge25519_p1p1_to_p3.s
    ge4x_add_p1p1.s
    ge4x_double_p1p1.s
    ge4x_lookup.s
    ge4x_lookup_niels.s
    ge4x_niels_add_p1p1.s
    gfe4x_add.s
    gfe4x_mul.s
    gfe4x_square.s
    gfe4x_sub.s)

set(EDWARDS25519_WIN64_ASM_SOURCES
    edwards25519_win64.asm)

set(EDWARDS25519_ASM_SUPPORT_SOURCES
    ge4x.c
    ge4x_pack.c
    ge4x_unpack_vartime.c
    gfe4x.c
    gfe4x_getparity.c
    gfe4x_iseq_vartime.c
    gfe4x_nsquare.c
    gfe4x_pow2523.c)

set(EDWARDS25519_REF_SOURCES
    fe25519_ref.c
    ge25519_ref.c
    ge4x_ref.c)

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

set_target_properties(cryptoToolsEdwards25519Objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

target_include_directories(cryptoToolsEdwards25519Objects PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../..
    ${CMAKE_CURRENT_BINARY_DIR}/../../..)

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

target_sources(cryptoTools PRIVATE
    $<TARGET_OBJECTS:cryptoToolsEdwards25519Objects>)
