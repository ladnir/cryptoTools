project(cryptoTools)

get_directory_property(hasParent PARENT_DIRECTORY)

# add the source files 
file(GLOB_RECURSE SRCS *.cpp *.c)
add_library(cryptoTools STATIC ${SRCS})
# make projects that include cryptoTools use this as an include folder
target_include_directories(cryptoTools PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/..")
target_include_directories(cryptoTools PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..")



if(NOT MSVC)
    target_compile_options(cryptoTools PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-std=c++14> -pthread)
    target_link_options(cryptoTools PUBLIC -pthread)

    if(ENABLE_SSE)
        target_compile_options(cryptoTools PUBLIC -maes -msse2 -msse3 -msse4.1 -mpclmul)
    endif()
endif()

#############################################
#            Install                        #
#############################################

install(DIRECTORY . DESTINATION include/cryptoTools FILES_MATCHING PATTERN "*.h")
install(DIRECTORY gsl DESTINATION include/cryptoTools)
install(TARGETS cryptoTools DESTINATION lib)


###########################################################################  
#                        Link external libraries                          #
#                        -----------------------                          #
#                                                                         #
#  Define the expected location for miracl and boost.                     #
#  Boost will be found using the findBoost  module in CMake               #
#  It should look in the location specified and then look elsewhere       # 
#                                                                         #
###########################################################################  


include("${CMAKE_CURRENT_SOURCE_DIR}/../cmake/cryptoToolsDepHelper.cmake")

## Relic
###########################################################################

if (ENABLE_RELIC)
  target_include_directories(cryptoTools PUBLIC ${RLC_INCLUDE_DIR}) 
  target_link_libraries(cryptoTools ${RLC_LIBRARY})
endif (ENABLE_RELIC)

## WolfSSL
###########################################################################

if(ENABLE_WOLFSSL)
  target_include_directories(cryptoTools PUBLIC "${WOLFSSL_LIB_INCLUDE_DIRS}") 
  target_link_libraries(cryptoTools ${WOLFSSL_LIB})

endif(ENABLE_WOLFSSL)

## Boost
###########################################################################

if(ENABLE_BOOST)
    target_include_directories(cryptoTools PUBLIC ${Boost_INCLUDE_DIR}) 
    target_link_libraries(cryptoTools ${Boost_LIBRARIES})
endif()
