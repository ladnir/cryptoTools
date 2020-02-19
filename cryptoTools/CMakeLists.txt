project(cryptoTools)

get_directory_property(hasParent PARENT_DIRECTORY)

# add the source files 
file(GLOB_RECURSE SRCS *.cpp *.c)
add_library(cryptoTools STATIC ${SRCS})
# make projects that include cryptoTools use this as an include folder
target_include_directories(cryptoTools PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..")


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


## Miracl
###########################################################################

if (ENABLE_MIRACL)

  set(Miracl_Dirs "${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/linux/miracl/")

  set(Miracl_Lib_Dirs "${Miracl_Dirs}/miracl/source/")
  find_library(MIRACL_LIB NAMES miracl  HINTS "${Miracl_Lib_Dirs}")

  # if we cant fint it, throw an error
  if(NOT MIRACL_LIB)
      message(FATAL_ERROR "Failed to find miracl at " ${Miracl_Lib_Dirs})
  endif()
  message(STATUS "MIRACL_LIB:  ${MIRACL_LIB}")

  target_include_directories(cryptoTools PUBLIC "${Miracl_Dirs}") 
  target_link_libraries(cryptoTools ${MIRACL_LIB})

  INSTALL(DIRECTORY "${Miracl_Dirs}/miracl/include/" DESTINATION include)
  INSTALL(FILES ${MIRACL_LIB} DESTINATION lib)

endif(ENABLE_MIRACL)


## Relic
###########################################################################

if (ENABLE_RELIC)
  find_package(Relic REQUIRED)

  if (NOT Relic_FOUND)
    message(FATAL_ERROR "Failed to find Relic")
  endif (NOT Relic_FOUND)

  message(STATUS "Relic_LIB:  ${RELIC_LIBRARIES} ${RLC_LIBRARY}")
  message(STATUS "Relic_inc:  ${RELIC_INCLUDE_DIR} ${RLC_INCLUDE_DIR}\n")

  target_include_directories(cryptoTools PUBLIC ${RELIC_INCLUDE_DIR} ${RLC_INCLUDE_DIR}) 
  target_link_libraries(cryptoTools ${RELIC_LIBRARIES} ${RLC_LIBRARY})

endif (ENABLE_RELIC)

## WolfSSL
###########################################################################

if(ENABLE_WOLFSSL)

  if(NOT DEFINED WolfSSL_DIR)
    set(WolfSSL_DIR "/usr/local/")
  endif()
  

  find_library(WOLFSSL_LIB NAMES wolfssl  HINTS "${WolfSSL_DIR}")
  set(WOLFSSL_LIB_INCLUDE_DIRS "${WolfSSL_DIR}include/")
  
  # if we cant fint it, throw an error
  if(NOT WOLFSSL_LIB)
      message(FATAL_ERROR "Failed to find WolfSSL at " ${WolfSSL_DIR})
  endif()

  message(STATUS "WOLFSSL_LIB:  ${WOLFSSL_LIB}")
  message(STATUS "WOLFSSL_INC:  ${WOLFSSL_LIB_INCLUDE_DIRS}\n")

  target_include_directories(cryptoTools PUBLIC "${WOLFSSL_LIB_INCLUDE_DIRS}") 
  target_link_libraries(cryptoTools ${WOLFSSL_LIB})

endif(ENABLE_WOLFSSL)

## Boost
###########################################################################

set(BOOST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/linux/boost/")

set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)

macro(findBoost)
  find_package(Boost 1.69.0 COMPONENTS system thread)
endmacro()

# then look at system dirs
if(NOT Boost_FOUND)
  #set(Boost_NO_SYSTEM_PATHS  OFF)
  findBoost()
endif()

if(NOT Boost_FOUND)
    message(FATAL_ERROR "Failed to find boost 1.69.0 or newer. Looked at system dirs and: " ${BOOST_ROOT})
endif()

target_include_directories(cryptoTools PUBLIC ${Boost_INCLUDE_DIR}) 
target_link_libraries(cryptoTools ${Boost_LIBRARIES})

message(STATUS "Boost_LIB: ${Boost_LIBRARIES}" )
message(STATUS "Boost_INC: ${Boost_INCLUDE_DIR}\n\n" )
