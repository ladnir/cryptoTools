cmake_minimum_required (VERSION 3.18)
if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif (POLICY CMP0048)

project(cryptoTools VERSION 1.10.1)




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
	else()
		# Select flags.
		set(CMAKE_C_FLAGS "-Wall -Wfatal-errors")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_C_FLAGS}")
		SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
		SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb")
		SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -ggdb")
	endif()
	#set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)

endif()


macro(EVAL var)
     if(${ARGN})
         set(${var} ON)
     else()
         set(${var} OFF)
     endif()
endmacro()

if(DEFINED OC_PIC)
	message("warning, setting ENABLE_PIC as OC_PIC = ${OC_PIC}")
	set(ENABLE_PIC ${OC_PIC})
	unset(OC_PIC CACHE)
endif()


#############################################
#                  CONFIGURE                #
#############################################
option(ENABLE_SPAN_LITE "use the span-lite library" ON)
option(ENABLE_GMP       "use the GMP library" OFF)
option(ENABLE_RELIC     "use the relic library" OFF)
option(ENABLE_SODIUM    "use libsodium" OFF)
option(ENABLE_CIRCUITS  "compile the circuit module" OFF)
option(ENABLE_NET_LOG   "compile with network logging" OFF)
option(ENABLE_WOLFSSL   "compiler with WolfSSL enabled" OFF)
option(ENABLE_SSE       "compile with SSE instructions" ON)
option(ENABLE_AVX       "compile with AVX instructions" ${ENABLE_SSE})
option(ENABLE_BOOST     "compile with BOOST networking integration" OFF)
option(ENABLE_OPENSSL   "compile with OpenSSL networking integration" OFF)
option(ENABLE_ASAN      "build with asan" OFF)
option(ENABLE_PIC       "compile with -fPIC " OFF)
option(VERBOSE_FETCH    "" ON)

if(NOT DEFINED CRYPTO_TOOLS_STD_VER)
	set(CRYPTO_TOOLS_STD_VER  17)
endif()
if(NOT ENABLE_SSE AND ENABLE_AVX)
	message("AVX requires SSE to be enabled.")
	set(ENABLE_AVX OFF)
endif()

option(FETCH_AUTO      "automatically download and build dependencies" OFF)

#option(FETCH_SPAN_LITE		"download and build span" OFF))
EVAL(FETCH_SPAN_LITE_IMPL 
	(DEFINED FETCH_SPAN_LITE AND FETCH_SPAN_LITE) OR
	((NOT DEFINED FETCH_SPAN_LITE) AND (FETCH_AUTO AND ENABLE_SPAN_LITE)))

#option(FETCH_SPAN_LITE		"download and build span" OFF))
EVAL(FETCH_GMP_IMPL 
	(DEFINED FETCH_GMP AND FETCH_GMP) OR
	((NOT DEFINED FETCH_GMP) AND (FETCH_AUTO AND ENABLE_GMP)))

#option(FETCH_RELIC		"download and build Relic" OFF))
EVAL(FETCH_RELIC_IMPL 
	(DEFINED FETCH_RELIC AND FETCH_RELIC) OR
	((NOT DEFINED FETCH_RELIC) AND (FETCH_AUTO AND ENABLE_RELIC)))

#option(FETCH_SODIUM	"download and build Sodium" OFF))
EVAL(FETCH_SODIUM_IMPL 
	(DEFINED FETCH_SODIUM AND FETCH_SODIUM) OR
	((NOT DEFINED FETCH_SODIUM) AND (FETCH_AUTO AND ENABLE_SODIUM)))
	
#option(FETCH_BOOST	"download and build Boost" OFF))
EVAL(FETCH_BOOST_IMPL 
	(DEFINED FETCH_BOOST AND FETCH_BOOST) OR
	((NOT DEFINED FETCH_BOOST) AND (FETCH_AUTO AND ENABLE_BOOST)))

if(ENABLE_BOOST)
	set(ENABLE_COPROTO true)
endif()

#option(FETCH_BOOST	"download and build Boost" OFF))
EVAL(FETCH_COPROTO_IMPL 
	(DEFINED FETCH_COPROTO AND FETCH_COPROTO) OR
	((NOT DEFINED FETCH_COPROTO) AND (FETCH_AUTO AND ENABLE_COPROTO)))

	
EVAL(FETCH_LIBDIVIDE_IMPL 
	(DEFINED FETCH_LIBDIVIDE AND FETCH_LIBDIVIDE) OR
	((NOT DEFINED FETCH_LIBDIVIDE) AND (FETCH_AUTO)))


option(VERBOSE_FETCH        "Print build info for fetched libraries" ON)



message(STATUS "cryptoTools options\n=======================================================")

message(STATUS "Option: CRYPTO_TOOLS_STD_VER  = ${CRYPTO_TOOLS_STD_VER}\n")

message(STATUS "Option: NO_SYSTEM_PATH    = ${NO_SYSTEM_PATH}")
message(STATUS "Option: FETCH_AUTO        = ${FETCH_AUTO}")
message(STATUS "Option: VERBOSE_FETCH     = ${VERBOSE_FETCH}\n")

message(STATUS "Option: FETCH_RELIC       = ${FETCH_RELIC}")
message(STATUS "Option: FETCH_SODIUM      = ${FETCH_SODIUM}")
message(STATUS "Option: FETCH_BOOST       = ${FETCH_BOOST}")
message(STATUS "Option: FETCH_COPROTO     = ${FETCH_COPROTO}")
message(STATUS "Option: FETCH_LIBDIVIDE   = ${FETCH_LIBDIVIDE_IMPL}\n")

message(STATUS "Option: CMAKE_BUILD_TYPE  = ${CMAKE_BUILD_TYPE}\n\tRelease\n\tDebug\n\tRelWithDebInfo")
message(STATUS "Option: ENABLE_SPAN_LITE  = ${ENABLE_SPAN_LITE}")
message(STATUS "Option: ENABLE_GMP        = ${ENABLE_GMP}")
message(STATUS "Option: ENABLE_RELIC      = ${ENABLE_RELIC}")
message(STATUS "Option: ENABLE_SODIUM     = ${ENABLE_SODIUM}")
message(STATUS "Option: ENABLE_BOOST      = ${ENABLE_BOOST}")
message(STATUS "Option: ENABLE_OPENSSL    = ${ENABLE_OPENSSL}")
message(STATUS "Option: ENABLE_COPROTO    = ${ENABLE_COPROTO}")
message(STATUS "Option: ENABLE_CIRCUITS   = ${ENABLE_CIRCUITS}")

message(STATUS "Option: ENABLE_SSE        = ${ENABLE_SSE}")
message(STATUS "Option: ENABLE_AVX        = ${ENABLE_AVX}")
message(STATUS "Option: ENABLE_PIC        = ${ENABLE_PIC}")
message(STATUS "Option: ENABLE_ASAN       = ${ENABLE_ASAN}\n\n")


#############################################
#       cryptoTools, tests, frontend        #
#############################################

include("${CMAKE_CURRENT_LIST_DIR}/cmake/cryptoToolsDepHelper.cmake")


add_subdirectory(cryptoTools)
add_subdirectory(tests_cryptoTools)
add_subdirectory(frontend_cryptoTools)

configure_file(cryptoTools/Common/config.h.in "cryptoTools/Common/config.h" )


include("cmake/install.cmake")
