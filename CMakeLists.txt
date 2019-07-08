cmake_minimum_required (VERSION 2.8)


option(ENABLE_MIRACL   "use the miracl library" OFF)
option(ENABLE_RELIC    "use the relic library" OFF)
option(ENABLE_CIRCUITS "compile the circuit module" OFF)
option(ENABLE_CPP_14   "compile with the c++14" ON)
set(ENABLE_FULL_GSL ${ENABLE_CPP_14})


if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")

	############################################
	#          If top level cmake              #
	############################################

	set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
	set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
	set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)

	
	set(CMAKE_C_FLAGS "-ffunction-sections -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread -fPIC -Wno-ignored-attributes")
	set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}")

	if(ENABLE_CPP_14)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")	
	else() 	
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
	endif()

	# Set a default build type for single-configuration
	# CMake generators if no build type is set.
	if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
	   SET(CMAKE_BUILD_TYPE Release)
	endif()

	if(NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release")
	  message(WARNING "\nConfiguration NOT set to Release. Please call cmake with -DCMAKE_BUILD_TYPE=Release  instead of ${CMAKE_BUILD_TYPE}")

		if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
		  #message(WARNING "Debug build.")
		elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release") 
		  #message(WARNING "Release build.")
		elseif("${CMAKE_BUILD_TYPE}" STREQUAL  "RELWITHDEBINFO")
		  #message(WARNING "RELWITHDEBINFO=Release with debug info build.")
		else()
		  message(ERROR ": Unknown build type - ${CMAKE_BUILD_TYPE}  Please use one of Debug, Release, or RELWITHDEBINFO\n\n" )
		endif()
	endif()

	# Select flags.
	SET(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG") 
	SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb -rdynamic")
	SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -ggdb -rdynamic")
	
	
endif() 




#############################################
#                  CONFIGURE                #
#############################################
find_program(NASM nasm)




if(NOT NASM)
	option(ENABLE_NASM "compile using NASM" OFF)
else(NOT NASM)
	option(ENABLE_NASM "compile using NASM" ON)
endif(NOT NASM)

message(STATUS "Option: ENABLE_MIRACL     = ${ENABLE_MIRACL}")
message(STATUS "Option: ENABLE_RELIC      = ${ENABLE_RELIC}")
message(STATUS "Option: ENABLE_CIRCUITS   = ${ENABLE_CIRCUITS}")
message(STATUS "Option: ENABLE_CPP_14     = ${ENABLE_CPP_14}")
message(STATUS "Option: ENABLE_NASM       = ${ENABLE_NASM}")


if(NOT ENABLE_CPP_14)
	set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}  -Wno-narrowing")
endif()

configure_file(cryptoTools/Common/config.h.in cryptoTools/Common/config.h)

#############################################
#       cryptoTools, tests, frontend        #
#############################################
include_directories(${CMAKE_CURRENT_SOURCE_DIR}) 


add_subdirectory(cryptoTools)
add_subdirectory(tests_cryptoTools)
add_subdirectory(frontend_cryptoTools)

install(FILES cryptotools-config.cmake DESTINATION cmake/)
