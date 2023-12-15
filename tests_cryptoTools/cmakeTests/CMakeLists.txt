 cmake_minimum_required(VERSION 3.15)
project(cmakeTest)
add_executable(main main.cpp)

find_package(cryptoTools REQUIRED HINTS ${CRYPTOTOOLS_HINT})

target_link_libraries(main oc::cryptoTools)


if(MSVC)
    target_compile_options(main PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${CRYPTO_TOOLS_STD_VER}>)
    
else()
    target_compile_options(main PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${CRYPTO_TOOLS_STD_VER}>)
endif()