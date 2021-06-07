

file(GLOB_RECURSE SRCS *.cpp)
include_directories(${CMAKE_SOURCE_DIR})
add_library(tests_cryptoTools STATIC ${SRCS})

# make projects that include cryptoTools use this as an include folder
target_include_directories(tests_cryptoTools PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 
target_include_directories(tests_cryptoTools PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:include>) 
target_link_libraries(tests_cryptoTools cryptoTools)




#############################################
#            Install                        #
#############################################

