 cmake_minimum_required(VERSION 3.15)
project(cmakeTest)

add_executable(main main.cpp)

find_package(cryptoTools REQUIRED HINTS ${CRYPTOTOOLS_HINT})

target_link_libraries(main oc::cryptoTools)