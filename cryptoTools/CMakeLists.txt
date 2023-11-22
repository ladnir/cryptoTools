project(cryptoTools)

include(FindPkgConfig)

get_directory_property(hasParent PARENT_DIRECTORY)

# add the source files
file(GLOB_RECURSE SRCS *.cpp *.c)
add_library(cryptoTools STATIC ${SRCS})

# make projects that include cryptoTools use this as an include folder
target_include_directories(cryptoTools PUBLIC
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>)
target_include_directories(cryptoTools PUBLIC
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>)


if(MSVC)
    if(ENABLE_ASAN)
        message("Warning: ASAN is enabled for cryptoTools")
        target_compile_options(cryptoTools PUBLIC "/fsanitize=address")
    endif()

    target_compile_options(cryptoTools PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${CRYPTO_TOOLS_STD_VER}>)
    
else()
    target_compile_options(cryptoTools PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${CRYPTO_TOOLS_STD_VER}> -pthread)

    target_link_options(cryptoTools PUBLIC -pthread)


    if(ENABLE_SSE)
        target_compile_options(cryptoTools PUBLIC -maes -msse2 -msse3 -mssse3 -msse4.1 -mpclmul)
    endif()
    if(ENABLE_AVX)
        target_compile_options(cryptoTools PUBLIC -mavx2)
    endif()

    if(ENABLE_PIC)
        target_compile_options(cryptoTools PUBLIC -fPIC)
    endif()

    
    if(ENABLE_ASAN)
        message("Warning: ASAN is enabled for cryptoTools")
        target_compile_options(cryptoTools PUBLIC "-fsanitize=address")
        target_link_options(cryptoTools PUBLIC "-fsanitize=address")
    endif()
endif()


## span-lite
###########################################################################

if(ENABLE_SPAN_LITE)
    target_link_libraries(cryptoTools nonstd::span-lite)
endif()

## span-lite
###########################################################################

if (ENABLE_SPAN_LITE)
  target_link_libraries(cryptoTools nonstd::span-lite)
endif (ENABLE_SPAN_LITE)

## Relic
###########################################################################

if (ENABLE_RELIC)
  target_link_libraries(cryptoTools relic)
endif (ENABLE_RELIC)

# libsodium
###########################################################################

if (ENABLE_SODIUM)
  target_link_libraries(cryptoTools sodium)
endif (ENABLE_SODIUM)


# coproto
###########################################################################

if (ENABLE_COPROTO)
  target_link_libraries(cryptoTools coproto::coproto)
endif (ENABLE_COPROTO)


if(ENABLE_GMP)
    target_link_libraries(cryptoTools GMP::libgmp GMP::libgmpxx)
endif()

### WolfSSL
############################################################################
#
#if(ENABLE_WOLFSSL)
#  target_include_directories(cryptoTools PUBLIC
#                    $<BUILD_INTERFACE:${WOLFSSL_LIB_INCLUDE_DIRS}>
#                    $<INSTALL_INTERFACE:>)
#  target_link_libraries(cryptoTools ${WOLFSSL_LIB})
#endif(ENABLE_WOLFSSL)
#
### Boost
############################################################################
#
#
#if(ENABLE_BOOST)
#    target_include_directories(cryptoTools PUBLIC
#                    $<BUILD_INTERFACE:${Boost_INCLUDE_DIR}>
#                    $<INSTALL_INTERFACE:>)
#    target_link_libraries(cryptoTools ${Boost_LIBRARIES})
#endif()



