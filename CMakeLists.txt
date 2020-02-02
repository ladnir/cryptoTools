cmake_minimum_required (VERSION 2.8)

project(cryptoTools)


if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")

	############################################
	#          If top level cmake              #
	############################################

	if(${CMAKE_VERSION} VERSION_LESS "3.12.0") 
		message("Please consider updating CMake to 3.12+")
	endif()

	set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
	set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
	set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)

	
	set(CMAKE_C_FLAGS "-ffunction-sections -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread -fPIC -Wno-ignored-attributes")
	set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}")

	#if(ENABLE_CPP_14)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")	
	#else() 	
	#	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
	#endif()

	# Set a default build type for single-configuration
	# CMake generators if no build type is set.
	if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
	   SET(CMAKE_BUILD_TYPE Release)
	endif()

	# Select flags.
	SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG") 
	SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb")
	SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -ggdb")
	
endif() 




#############################################
#                  CONFIGURE                #
#############################################
find_program(NASM nasm)

option(ENABLE_MIRACL    "use the miracl library" OFF)
option(ENABLE_RELIC     "use the relic library" OFF)
option(ENABLE_CIRCUITS  "compile the circuit module" OFF)
option(ENABLE_CPP_14    "compile with the c++14" ON)
option(ENABLE_NET_LOG   "compile with network logging" OFF)
option(ENABLE_WOLFSSL   "conpiler with WolfSSL enabled" OFF)

set(ENABLE_FULL_GSL ${ENABLE_CPP_14})

# make these visable to the parent scope
set(ENABLE_MIRACL ${ENABLE_MIRACL} PARENT_SCOPE)
set(ENABLE_RELIC  ${ENABLE_RELIC}  PARENT_SCOPE)

message(STATUS "cryptoTools options\n=======================================================")

message(STATUS "Option: CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}\n\tRelease\n\tDebug\n\tRELWITHDEBINFO")
message(STATUS "Option: ENABLE_MIRACL     = ${ENABLE_MIRACL}")
message(STATUS "Option: ENABLE_RELIC      = ${ENABLE_RELIC}")
message(STATUS "Option: ENABLE_CIRCUITS   = ${ENABLE_CIRCUITS}")
#message(STATUS "Option: ENABLE_CPP_14     = ${ENABLE_CPP_14}")
message(STATUS "Option: ENABLE_NET_LOG    = ${ENABLE_NET_LOG}")
message(STATUS "Option: ENABLE_WOLFSSL    = ${ENABLE_WOLFSSL}\n\n")

if(NOT ENABLE_CPP_14)
	set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}  -Wno-narrowing")
endif()

configure_file(cryptoTools/Common/config.h.in "${CMAKE_CURRENT_SOURCE_DIR}/cryptoTools/Common/config.h" )

#############################################
#       cryptoTools, tests, frontend        #
#############################################
include_directories(${CMAKE_CURRENT_SOURCE_DIR}) 


add_subdirectory(cryptoTools)
add_subdirectory(tests_cryptoTools)
add_subdirectory(frontend_cryptoTools)

install(FILES cryptotools-config.cmake DESTINATION cmake/)
