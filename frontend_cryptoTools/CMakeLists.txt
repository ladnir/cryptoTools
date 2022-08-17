

file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR})

add_executable(frontend_cryptoTools  ${SRCS})
target_link_libraries(frontend_cryptoTools cryptoTools tests_cryptoTools)


if(NOT MSVC)
    target_compile_options(frontend_cryptoTools PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${CRYPTO_TOOLS_STD_VER}>)
endif()
