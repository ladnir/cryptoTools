cmake_policy(PUSH)
cmake_policy(SET CMP0057 NEW)
cmake_policy(SET CMP0045 NEW)
cmake_policy(SET CMP0074 NEW)


# a macro that resolved the linked libraries and includes
# of a target.
macro(OC_getAllLinkedLibraries iTarget LIBRARIES INCLUDES)
   if(NOT TARGET ${iTarget})
        message(WARNING "${iTarget} is not a target")
    else()

        # get inlcude
        get_target_property(TARGET_INCS ${iTarget} INTERFACE_INCLUDE_DIRECTORIES)

        # if it has any, add any new ones.
        if(TARGET_INCS)
            FOREACH(path ${TARGET_INCS})

                if(NOT ${path} IN_LIST ${INCLUDES})
                    list(APPEND ${INCLUDES} ${path})
                endif()
            ENDFOREACH()
        else()
            #message("iTarget no include ${iTarget}")
        endif()

        # get the location of this libraries
        get_target_property(type ${iTarget} TYPE)
        if (${type} STREQUAL "INTERFACE_LIBRARY")
            #message("iTarget interface target ${iTarget}")
            get_target_property(path ${iTarget} INTERFACE_LINK_LIBRARIES)
        else()
            #message("iTarget normal target ${iTarget}, ${type}")

            get_target_property(path ${iTarget} LOCATION)
        endif()
        if(NOT ${path} IN_LIST ${LIBRARIES})
            if(path)
                list(APPEND ${LIBRARIES} ${path})
            else()
                #message("iTarget no location ${iTarget}, ${path}")
            endif()
        endif()

        # recurse on the linked libraries.
        get_target_property(linkedLibrairies ${iTarget} INTERFACE_LINK_LIBRARIES)

        #message(STATUS "\n\n ${iTarget} -> ${linkedLibrairies}")

        if(NOT "${linkedLibrairies}" STREQUAL "")
            FOREACH(linkedLibrary ${linkedLibrairies})
                if(TARGET ${linkedLibrary})
                    OC_getAllLinkedLibraries(${linkedLibrary} ${LIBRARIES} ${INCLUDES})
                elseif(linkedLibrary AND (NOT ${linkedLibrary} IN_LIST ${LIBRARIES}))
                    #message("\n\n\nnon-target lib ${linkedLibrary}\n\n\n")

                    list(APPEND ${LIBRARIES} ${linkedLibrary})
                endif()
            ENDFOREACH()
        endif()
    endif()
endmacro()

if(NOT DEFINED OC_THIRDPARTY_HINT)
    if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/cryptoToolsFindBuildDir.cmake)
        # we currenty are in the cryptoTools source tree, cryptoTools/cmake
        if(MSVC AND ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	        set(TARGET_SYSTEM "win")
        elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux" OR ${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	        set(TARGET_SYSTEM "unix")
        else()
	        message(WARNING "Unsupported system ${CMAKE_SYSTEM_NAME}")
            set(TARGET_SYSTEM "unknown")
        endif()

        set(OC_THIRDPARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/thirdparty)
        set(OC_THIRDPARTY_HINT ${OC_THIRDPARTY_DIR}/${TARGET_SYSTEM})
    endif()
endif()

set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};${OC_THIRDPARTY_HINT}")

set(OC_THIRDPARTY_INSTALL_PREFIX ${OC_THIRDPARTY_HINT})
message(STATUS "Thirdparty dependencies installed in ${OC_THIRDPARTY_INSTALL_PREFIX}")

## Relic
###########################################################################

include(FindPackageHandleStandardArgs)

if(ENABLE_RELIC)
    find_path(RLC_INCLUDE_DIR "relic/relic.h")
    find_library(RLC_LIBRARY NAMES relic relic_s)
    if(NOT RLC_INCLUDE_DIR OR NOT RLC_LIBRARY)
    	message(STATUS "Setting up Relic...")
        # Download and configure
        if(EXISTS ${OC_THIRDPARTY_DIR}/relic/CMakeCache.txt)
            file(REMOVE ${OC_THIRDPARTY_DIR}/relic/CMakeCache.txt)
        endif()
    	execute_process(
    		COMMAND ${CMAKE_COMMAND} -DCMAKE_INSTALL_PREFIX=${OC_THIRDPARTY_INSTALL_PREFIX} -G "${CMAKE_GENERATOR}" .
    		OUTPUT_QUIET
    		RESULT_VARIABLE result
    		WORKING_DIRECTORY ${OC_THIRDPARTY_DIR}/relic
    	)
    	if(result)
    		message(WARNING "Failed to download Relic (${result})")
    	endif()

        # Build and install
    	execute_process(
    		COMMAND ${CMAKE_COMMAND} --build . --clean-first
    		OUTPUT_QUIET
    		RESULT_VARIABLE result
    		WORKING_DIRECTORY ${OC_THIRDPARTY_DIR}/relic
    	)
    	if(result)
    		message(WARNING "Failed to build Relic (${result})")
    	endif()

    	find_path(RLC_INCLUDE_DIR "relic/relic.h")
    	find_library(RLC_LIBRARY NAMES relic relic_s)
    	if(NOT RLC_INCLUDE_DIR OR NOT RLC_LIBRARY)
            message(FATAL_ERROR "Failed to find Relic.\n\nRLC_LIBRARY=${RLC_LIBRARY}\nRLC_INCLUDE_DIR=${RLC_INCLUDE_DIR}\n Looked at RELIC_ROOT=${RELIC_ROOT}; and system installs.\n OC_THIRDPARTY_HINT=${OC_THIRDPARTY_HINT}\n")
    	endif()
    endif()

    set(RLC_LIBRARIES ${RLC_LIBRARY})
    set(RLC_INCLUDE_DIRS ${RLC_INCLUDE_DIR})

    message(STATUS "Relic_LIB:           ${RLC_LIBRARY}")
    message(STATUS "Relic_inc:           ${RLC_INCLUDE_DIR}")

    add_library(relic STATIC IMPORTED)

    set_property(TARGET relic PROPERTY IMPORTED_LOCATION ${RLC_LIBRARY})
    target_include_directories(relic INTERFACE
                    $<BUILD_INTERFACE:${RLC_INCLUDE_DIR}>
                    $<INSTALL_INTERFACE:>)
endif(ENABLE_RELIC)

# libsodium
###########################################################################

if(ENABLE_SODIUM)
    find_path(SODIUM_INCLUDE_DIRS sodium.h)
    find_library(SODIUM_LIBRARIES NAMES sodium)
    if(NOT SODIUM_INCLUDE_DIRS OR NOT SODIUM_LIBRARIES)
    	message(STATUS "Setting up Sodium...")
        # Download and configure
        if(EXISTS ${OC_THIRDPARTY_DIR}/libsodium/CMakeCache.txt)
            file(REMOVE ${OC_THIRDPARTY_DIR}/libsodium/CMakeCache.txt)
        endif()
    	execute_process(
    		COMMAND ${CMAKE_COMMAND} -DCMAKE_INSTALL_PREFIX=${OC_THIRDPARTY_INSTALL_PREFIX} -G "${CMAKE_GENERATOR}" .
    		OUTPUT_QUIET
    		RESULT_VARIABLE result
    		WORKING_DIRECTORY ${OC_THIRDPARTY_DIR}/libsodium
    	)
    	if(result)
    		message(WARNING "Failed to download Sodium (${result})")
    	endif()

        # Build and install
    	execute_process(
    		COMMAND ${CMAKE_COMMAND} --build . --clean-first
    		OUTPUT_QUIET
    		RESULT_VARIABLE result
    		WORKING_DIRECTORY ${OC_THIRDPARTY_DIR}/libsodium
    	)
    	if(result)
    		message(WARNING "Failed to download Sodium (${result})")
    	endif()

    	find_path(SODIUM_INCLUDE_DIRS sodium.h)
    	find_library(SODIUM_LIBRARIES NAMES sodium)
    	if(NOT SODIUM_INCLUDE_DIRS OR NOT SODIUM_INCLUDE_DIRS)
            message(FATAL_ERROR "Failed to find Sodium.\n  OC_THIRDPARTY_HINT=${OC_THIRDPARTY_HINT}\n  SODIUM_INCLUDE_DIRS=${SODIUM_INCLUDE_DIRS}\n  SODIUM_LIBRARIES=${SODIUM_LIBRARIES}")
    	endif()
    endif()

    set(SODIUM_MONTGOMERY ON CACHE BOOL "SODIUM_MONTGOMERY...")

    message(STATUS "SODIUM_INCLUDE_DIRS: ${SODIUM_INCLUDE_DIRS}")
    message(STATUS "SODIUM_LIBRARIES:    ${SODIUM_LIBRARIES}")
    message(STATUS "SODIUM_MONTGOMERY:   ${SODIUM_MONTGOMERY}")

    add_library(sodium STATIC IMPORTED)

    set_property(TARGET sodium PROPERTY IMPORTED_LOCATION ${SODIUM_LIBRARIES})
    target_include_directories(sodium INTERFACE
                    $<BUILD_INTERFACE:${SODIUM_INCLUDE_DIRS}>
                    $<INSTALL_INTERFACE:>)

    if(MSVC)
        target_compile_definitions(sodium INTERFACE SODIUM_STATIC=1)
    endif()

endif(ENABLE_SODIUM)

## WolfSSL
###########################################################################

if(ENABLE_WOLFSSL)

  if(NOT DEFINED WolfSSL_DIR)
    set(WolfSSL_DIR "/usr/local/")
  endif()


  find_library(WOLFSSL_LIB NAMES wolfssl HINTS "${WolfSSL_DIR}")
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

if(ENABLE_BOOST)
    if(MSVC)
        set(Boost_LIB_PREFIX "lib")
    endif()

    option(Boost_USE_DEBUG_RUNTIME "Set to ON whether to search and use the debug libraries" OFF)
    option(Boost_USE_MULTITHREADED "Set to OFF to use the non-multithreaded libraries (\"mt\" tag)" ON)
    option(Boost_USE_STATIC_LIBS "Set to ON to force the use of the static libraries" OFF)
    #set(Boost_DEBUG ON)  #<---------- Real life saver
    #message("BOOST_ROOT=${BOOST_ROOT}")

    macro(findBoost)
        if(MSVC)
            find_package(Boost 1.75.0 COMPONENTS system thread regex)
        else()
            find_package(Boost 1.75.0 COMPONENTS system thread)
        endif()
    endmacro()

    findBoost()
    if(NOT Boost_FOUND)
    	message(STATUS "Setting up Boost...")
        # Download and configure
        if(EXISTS ${OC_THIRDPARTY_DIR}/boost/CMakeCache.txt)
            file(REMOVE ${OC_THIRDPARTY_DIR}/boost/CMakeCache.txt)
        endif()
    	execute_process(
    		COMMAND ${CMAKE_COMMAND} -DCMAKE_INSTALL_PREFIX=${OC_THIRDPARTY_INSTALL_PREFIX} -DBoost_USE_MULTITHREADED=${Boost_USE_MULTITHREADED} -G "${CMAKE_GENERATOR}" .
    		OUTPUT_QUIET
    		RESULT_VARIABLE result
    		WORKING_DIRECTORY ${OC_THIRDPARTY_DIR}/boost
    	)
    	if(result)
    		message(WARNING "Failed to download Boost (${result})")
    	endif()

        # Build and install
    	execute_process(
    		COMMAND ${CMAKE_COMMAND} --build .. --clean-first
    		OUTPUT_QUIET
        	RESULT_VARIABLE result
    		WORKING_DIRECTORY ${OC_THIRDPARTY_DIR}/boost/src
    	)
    	if (result)
    		message(WARNING "Failed to build Boost ($result)")
    	endif()

        set(BOOST_ROOT ${OC_THIRDPARTY_INSTALL_PREFIX})
    	findBoost()
    	if(NOT Boost_FOUND)
        	message(FATAL_ERROR "Failed to find boost 1.75+ at \"${OC_THIRDPARTY_HINT}\" or at system install")
    	endif()
    endif()

    message(STATUS "Boost_LIBRARIES:     ${Boost_LIBRARIES}.")
    message(STATUS "Boost_INCLUDE_DIRS:  ${Boost_INCLUDE_DIRS}")

endif(ENABLE_BOOST)

# resort the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
cmake_policy(POP)