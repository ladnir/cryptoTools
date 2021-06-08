cmake_minimum_required (VERSION 3.15)
if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif (POLICY CMP0048)

project(cryptoTools VERSION 1.8.0)




if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")

	############################################
	#          If top level cmake              #
	############################################

	if(${CMAKE_VERSION} VERSION_LESS "3.12.0") 
		message("Please consider updating CMake to 3.12+")
	endif()


	# Set a default build type for single-configuration
	# CMake generators if no build type is set.
	if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
	   SET(CMAKE_BUILD_TYPE Release)
	endif()

	if(MSVC)
		# optionally add the following to CMAKE_PREFIX_PATH
		if(NOT DEFINED CMAKE_PREFIX_PATH AND NOT DEFINED NO_OC_DEFAULT_PREFIX)
			set(CMAKE_PREFIX_PATH 
				"c:/libs"
				"${CMAKE_CURRENT_SOURCE_DIR}/.."
				)
		endif()
	else()
		# Select flags.
		set(CMAKE_C_FLAGS "-Wall -Wfatal-errors")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS}")	
		SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG") 
		SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb")
		SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -ggdb")
	endif()

endif() 




#############################################
#                  CONFIGURE                #
#############################################

option(ENABLE_RELIC     "use the relic library" OFF)
option(ENABLE_SODIUM    "use libsodium" OFF)
option(ENABLE_CIRCUITS  "compile the circuit module" OFF)
option(ENABLE_CPP_14    "compile with the c++14" ON)
option(ENABLE_NET_LOG   "compile with network logging" OFF)
option(ENABLE_WOLFSSL   "conpiler with WolfSSL enabled" OFF)
option(ENABLE_SSE       "compile with SSE instrctions" ON)
option(ENABLE_BOOST     "compile with BOOST networing integration" ON)

set(ENABLE_FULL_GSL ${ENABLE_CPP_14})

message(STATUS "cryptoTools options\n=======================================================")

message(STATUS "Option: CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}\n\tRelease\n\tDebug\n\tRelWithDebInfo")
message(STATUS "Option: ENABLE_RELIC      = ${ENABLE_RELIC}")
message(STATUS "Option: ENABLE_SODIUM     = ${ENABLE_SODIUM}")
message(STATUS "Option: ENABLE_CIRCUITS   = ${ENABLE_CIRCUITS}")
message(STATUS "Option: ENABLE_NET_LOG    = ${ENABLE_NET_LOG}")
message(STATUS "Option: ENABLE_WOLFSSL    = ${ENABLE_WOLFSSL}")
message(STATUS "Option: ENABLE_SSE        = ${ENABLE_SSE}")
message(STATUS "Option: ENABLE_BOOST      = ${ENABLE_BOOST}\n\n")

if(NOT ENABLE_CPP_14)
	set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}  -Wno-narrowing")
endif()


#############################################
#       cryptoTools, tests, frontend        #
#############################################


add_subdirectory(cryptoTools)
add_subdirectory(tests_cryptoTools)
add_subdirectory(frontend_cryptoTools)

configure_file(cryptoTools/Common/config.h.in "cryptoTools/Common/config.h" )


include("cmake/install.cmake")