cmake_policy(PUSH)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0045 NEW)
cmake_policy(SET CMP0074 NEW)



if(MSVC)
    if(NOT DEFINED CMAKE_BUILD_TYPE)
        set(OC_BUILD_TYPE "Release")
    elseif(MSVC AND ${CMAKE_BUILD_TYPE} STREQUAL "RelWithDebInfo")
        set(OC_BUILD_TYPE "Release")
    else()
        set(OC_BUILD_TYPE ${CMAKE_BUILD_TYPE})
    endif()

    set(OC_CONFIG "x64-${OC_BUILD_TYPE}")
elseif(APPLE)
    set(OC_CONFIG "osx")
else()
    set(OC_CONFIG "linux")
endif()


if(NOT DEFINED OC_THIRDPARTY_HINT)

    if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/cryptoToolsFindBuildDir.cmake)
        # we currenty are in the cryptoTools source tree, cryptoTools/cmake
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../out/install/${OC_CONFIG}")
        
        if(NOT DEFINED OC_THIRDPARTY_INSTALL_PREFIX)
            set(OC_THIRDPARTY_INSTALL_PREFIX ${OC_THIRDPARTY_HINT})
        endif()
    else()
        # we currenty are in install tree, <install-prefix>/lib/cmake/cryptoTools
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../../..")
    endif()
endif()

set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${OC_THIRDPARTY_HINT};${CMAKE_PREFIX_PATH}")


## Span
###########################################################################

macro(FIND_SPAN)
    set(ARGS ${ARGN})
    if(FETCH_SPAN_LITE)
        list(APPEND ARGS NO_DEFAULT_PATH PATHS ${OC_THIRDPARTY_HINT})
    endif()
    find_package(span-lite ${ARGS})
endmacro()
    
if (FETCH_SPAN_LITE_IMPL)
    FIND_SPAN(QUIET)
    include("${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getSpanLite.cmake")
endif()

FIND_SPAN(REQUIRED)


## Relic
###########################################################################

macro(FIND_RELIC)
    set(ARGS ${ARGN})
    if(FETCH_RELIC)
        list(APPEND ARGS NO_DEFAULT_PATH PATHS ${OC_THIRDPARTY_HINT})
    endif()

    find_path(RLC_INCLUDE_DIR "relic/relic.h" PATH_SUFFIXES "/include/" ${ARGS})
    find_library(RLC_LIBRARY NAMES relic_s  PATH_SUFFIXES "/lib/" ${ARGS})
    if(EXISTS ${RLC_INCLUDE_DIR} AND EXISTS ${RLC_LIBRARY})
        set(RELIC_FOUND ON)
    else() 
        set(RELIC_FOUND OFF) 
    endif()
endmacro()
    
if(FETCH_RELIC_IMPL)
    FIND_RELIC()
    include(${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getRelic.cmake)
endif()


if (ENABLE_RELIC)
    
    FIND_RELIC()

    if(NOT RELIC_FOUND)
        message(FATAL_ERROR "could not find relic. Add -DFETCH_RELIC=ON or -DFETCH_ALL=ON to auto download.\n")
    endif()


    if(NOT TARGET relic)
        # does not property work on windows. Need to do a PR on relic.
        #find_package(RELIC REQUIRED HINTS "${OC_THIRDPARTY_HINT}")
        add_library(relic STATIC IMPORTED)
    
        set_property(TARGET relic PROPERTY IMPORTED_LOCATION ${RLC_LIBRARY})
        target_include_directories(relic INTERFACE 
                        $<BUILD_INTERFACE:${RLC_INCLUDE_DIR}>
                        $<INSTALL_INTERFACE:>)
    endif()
    message(STATUS "Relic_LIB:  ${RLC_LIBRARY}")
    message(STATUS "Relic_inc:  ${RLC_INCLUDE_DIR}\n")

endif()

# libsodium
###########################################################################

macro(FIND_SODIUM)
    set(ARGS ${ARGN})
    if(FETCH_SODIUM)
        list(APPEND ARGS NO_DEFAULT_PATH PATHS ${OC_THIRDPARTY_HINT})
    endif()
    find_path(SODIUM_INCLUDE_DIRS sodium.h PATH_SUFFIXES "/include/" ${ARGS})

    if(MSVC)
        set(SODIUM_LIB_NAME libsodium.lib)
    else()
        set(SODIUM_LIB_NAME libsodium.a)
    endif()
    
    find_library(SODIUM_LIBRARIES NAMES ${SODIUM_LIB_NAME} PATH_SUFFIXES "/lib/" ${ARGS})
    if(EXISTS ${SODIUM_INCLUDE_DIRS} AND EXISTS ${SODIUM_LIBRARIES})
        set(SODIUM_FOUND  ON)
    else() 
        set(SODIUM_FOUND  OFF) 
    endif()
endmacro()

if(FETCH_SODIUM_IMPL)
    FIND_SODIUM()
    include(${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getSodium.cmake)
endif()

if (ENABLE_SODIUM)
  
    FIND_SODIUM()

    if (NOT SODIUM_FOUND)
        message(FATAL_ERROR "Failed to find libsodium.\n Add -DFETCH_SODIUM=ON or -DFETCH_ALL=ON to auto download.")
    endif ()
    
    set(SODIUM_MONTGOMERY ON CACHE BOOL "SODIUM_MONTGOMERY...")

    message(STATUS "SODIUM_INCLUDE_DIRS:  ${SODIUM_INCLUDE_DIRS}")
    message(STATUS "SODIUM_LIBRARIES:  ${SODIUM_LIBRARIES}")
    message(STATUS "SODIUM_MONTGOMERY:  ${SODIUM_MONTGOMERY}\n")

    if(NOT TARGET sodium)
        add_library(sodium STATIC IMPORTED)
    
        set_property(TARGET sodium PROPERTY IMPORTED_LOCATION ${SODIUM_LIBRARIES})
        target_include_directories(sodium INTERFACE 
            $<BUILD_INTERFACE:${SODIUM_INCLUDE_DIRS}>
            $<INSTALL_INTERFACE:>)


        if(MSVC)
            target_compile_definitions(sodium INTERFACE SODIUM_STATIC=1)
        endif()
    endif()
endif (ENABLE_SODIUM)



## WolfSSL
###########################################################################

if(ENABLE_WOLFSSL)

  if(NOT DEFINED WolfSSL_DIR)
    set(WolfSSL_DIR "/usr/local/")
  endif()


  find_library(WOLFSSL_LIB NAMES wolfssl  HINTS "${WolfSSL_DIR}")
  set(WOLFSSL_LIB_INCLUDE_DIRS "${WolfSSL_DIR}include/")

  # if we cant find it, throw an error
  if(NOT WOLFSSL_LIB)
      message(FATAL_ERROR "Failed to find WolfSSL at " ${WolfSSL_DIR})
  endif()

  message(STATUS "WOLFSSL_LIB:  ${WOLFSSL_LIB}")
  message(STATUS "WOLFSSL_INC:  ${WOLFSSL_LIB_INCLUDE_DIRS}\n")

endif(ENABLE_WOLFSSL)


## Boost
###########################################################################

macro(FIND_BOOST)
    set(ARGS ${ARGN})
    if(FETCH_BOOST_IMPL)
        list(APPEND ARGS NO_DEFAULT_PATH  PATHS ${OC_THIRDPARTY_HINT} )
    endif()
    option(Boost_USE_MULTITHREADED "mt boost" ON)
    option(Boost_USE_STATIC_LIBS "static boost" ON)

    if(MSVC)
        option(Boost_LIB_PREFIX "Boost_LIB_PREFIX" "lib")
    endif()
    #set(Boost_DEBUG ON)  #<---------- Real life saver
 
    find_package(Boost 1.77.0 COMPONENTS system thread regex ${ARGS})
endmacro()

if(FETCH_BOOST_IMPL)
    FIND_BOOST(QUIET)
    include("${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getBoost.cmake")
endif()

if(ENABLE_BOOST)

    FIND_BOOST()
    if(NOT Boost_FOUND)
        message(FATAL_ERROR "Failed to find boost 1.77. Add -DFETCH_BOOST=ON or -DFETCH_ALL=ON to auto download.")
    endif()

    message(STATUS "Boost_LIB: ${Boost_LIBRARIES}" )
    message(STATUS "Boost_INC: ${Boost_INCLUDE_DIR}\n\n" )

endif()


# resort the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
cmake_policy(POP)