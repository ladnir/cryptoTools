
cmake_minimum_required (VERSION 3.15)

project (TestProj VERSION  1.0.0)

add_executable(main "src.cpp")

message("\n\nCMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}\n\n")

#if(NOT EXISTS ${CMAKE_PREFIX_PATH})
#	message(FATAL_ERROR "CMAKE_PREFIX_PATH does not #exist")
#endif()

find_package(cryptoTools REQUIRED)

target_link_libraries(main cryptoTools)

#message(STATUS "COPROTO_CPP20   = ${COPROTO_CPP20}")
#message(STATUS "COPROTO_LOGGING = ${COPROTO_LOGGING}")