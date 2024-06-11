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


#############################################
#       cryptoTools, tests, frontend        #
#############################################
include("${CMAKE_CURRENT_LIST_DIR}/cmake/cryptoToolsBuildOptions.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/cmake/cryptoToolsDepHelper.cmake")


add_subdirectory(cryptoTools)
add_subdirectory(tests_cryptoTools)
add_subdirectory(frontend_cryptoTools)

configure_file(cryptoTools/Common/config.h.in "cryptoTools/Common/config.h" )


include("cmake/install.cmake")
