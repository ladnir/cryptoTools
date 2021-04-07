cmake_minimum_required (VERSION 2.8)
if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif (POLICY CMP0048)

project(cryptoTools VERSION 1.7.0)




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

endif() 




#############################################
#                  CONFIGURE                #
#############################################
find_program(NASM nasm)

option(ENABLE_RELIC     "use the relic library" OFF)
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
message(STATUS "Option: ENABLE_CIRCUITS   = ${ENABLE_CIRCUITS}")
message(STATUS "Option: ENABLE_NET_LOG    = ${ENABLE_NET_LOG}")
message(STATUS "Option: ENABLE_WOLFSSL    = ${ENABLE_WOLFSSL}")
message(STATUS "Option: ENABLE_SSE        = ${ENABLE_SSE}")
message(STATUS "Option: ENABLE_BOOST      = ${ENABLE_BOOST}\n\n")

if(NOT ENABLE_CPP_14)
	set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}  -Wno-narrowing")
endif()


configure_file(cryptoTools/Common/config.h.in "cryptoTools/Common/config.h" )

#############################################
#       cryptoTools, tests, frontend        #
#############################################


add_subdirectory(cryptoTools)
add_subdirectory(tests_cryptoTools)
add_subdirectory(frontend_cryptoTools)

#install(FILES cryptotools-config.cmake DESTINATION cmake/)



#
#set(CMAKE_INCLUDE_CURRENT_DIR ON)
#set(CMAKE_INCLUDE_CURRENT_DIR_IN_INTERFACE ON)
#include(GenerateExportHeader)
#
#generate_export_header(cryptoTools)
#
#set_property(TARGET cryptoTools PROPERTY VERSION ${cryptoTools_VERSION})
#set_property(TARGET cryptoTools PROPERTY
#  INTERFACE_cryptoTools_MAJOR_VERSION 3)
#set_property(TARGET cryptoTools APPEND PROPERTY
#  COMPATIBLE_INTERFACE_STRING cryptoTools_MAJOR_VERSION
#)
#message(STATUS "---------------------- here 0")
#
#
#install(TARGETS cryptoTools EXPORT cryptoToolsTargets
#  LIBRARY DESTINATION lib
#  ARCHIVE DESTINATION lib
#  RUNTIME DESTINATION bin
#  INCLUDES DESTINATION include
#)
#message(STATUS "------------------- here 1")
#
#include(CMakePackageConfigHelpers)
#write_basic_package_version_file(
#  "${CMAKE_CURRENT_BINARY_DIR}/cryptoTools/cryptoToolsConfigVersion.cmake"
#  VERSION ${cryptoTools_VERSION}
#  COMPATIBILITY AnyNewerVersion
#)
#
#message(STATUS "------------------- here 2")
#
#export(EXPORT cryptoToolsTargets
#  FILE "${CMAKE_CURRENT_BINARY_DIR}/cryptoTools/cryptoToolsTargets.cmake"
#  NAMESPACE cryptoTools::
#)
#
#
#message(STATUS "------------------- here 3")
#
#configure_file(cmake/cryptoToolsConfig.cmake
#  "${CMAKE_CURRENT_BINARY_DIR}/cryptoTools/cryptoToolsConfig.cmake"
#  COPYONLY
#)
#
#
#message(STATUS "------------------- here 4")
#set(ConfigPackageLocation lib/cmake/cryptoTools)
#install(EXPORT cryptoToolsTargets
#  FILE
#    cryptoToolsTargets.cmake
#  NAMESPACE
#    cryptoTools::
#  DESTINATION
#    ${ConfigPackageLocation}
#)
#
#
#message(STATUS "------------------- here 5")
#
#install(
#  FILES
#    cmake/cryptoToolsConfig.cmake
#    "${CMAKE_CURRENT_BINARY_DIR}/cryptoTools/cryptoToolsConfigVersion.cmake"
#  DESTINATION
#    ${ConfigPackageLocation}
#  COMPONENT
#    Devel
#)
#
#
#message(STATUS "------------------- here 6")