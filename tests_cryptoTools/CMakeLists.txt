

file(GLOB_RECURSE SRCS *.cpp)
include_directories(${CMAKE_SOURCE_DIR})
add_library(tests_cryptoTools STATIC ${SRCS})

target_include_directories(tests_cryptoTools PUBLIC ${CMAKE_SOURCE_DIR}) 
target_link_libraries(tests_cryptoTools cryptoTools)
