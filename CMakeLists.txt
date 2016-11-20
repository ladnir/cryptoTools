

project(cryptoTools C CXX)


if($ENV{nasm} MATCHES "")
	message(WARNING "nasm environment variable NOT defined!!!!")

	# define this so that the asm is disabled.
	add_definitions(-DNO_INTEL_ASM_SHA1=1)
	set(shaNasmOutput )

else()
	set(shaNasm "${CMAKE_SOURCE_DIR}/cryptoTools/Crypto/asm/sha_lnx.S")
	set(shaNasmOutput "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/cryptoTools.dir/Crypto/sha_lnx.S.o")
	set(nasmScript "${CMAKE_SOURCE_DIR}/cryptoTools/nasm.sh")

	# couldn't figure out how to pass a command to build this
	# asm file so i just wrote a script that does the compile.
	# if you change this, update the nasm.sh script
	add_custom_command(
		OUTPUT ${shaNasmOutput} 
		DEPENDS ${shaNasm} ${nasmScript}
		COMMENT "${nasmScript}"
		COMMAND "${nasmScript}")

	# mark this asm output input to everything.
	add_custom_target(sha_asm ALL
		DEPENDS ${shaNasmOutput})
endif()


file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR}/cryptoTools)
add_library(cryptoTools ${SRCS} ${shaNasmOutput})




###########################################################################  
###########################################################################  
#                        Link external libraries                          #
#                        -----------------------                          #
#                                                                         #
#  Define the expected location for miracl and boost.                     #
#  Boost will be found using the findBoost  module in CMake               #
#  It should look in the location specified and then look elsewhere       # 
#                                                                         #
###########################################################################  
  
# here is where we expect these libraries to be. Boost will fall back to system location

set(Miracl_Lib_Dirs "${CMAKE_SOURCE_DIR}/thirdparty/linux/miracl/miracl/source/")
#set(Boost_Lib_Dirs "${CMAKE_SOURCE_DIR}/thirdparty/linux/boost/stage/lib/")

# default location for miracl
set(MIRACL_LIB "${Miracl_Lib_Dirs}libmiracl.a")


if(NOT EXISTS "MIRACL_LIB")

  # we failed to find it, try using find_library
  find_library(
    MIRACL_LIB 
    NAMES miracl  
    HINTS Miracl_Lib_Dirs)
  
  # if we still cant fint it, throw an error
  if(NOT MIRACL_LIB)
    Message(${MIRACL_LIB})
    message(FATAL_ERROR "Failed to find miracl at " ${Miracl_Lib_Dirs})
  endif()

endif()





set(BOOST_ROOT "${CMAKE_SOURCE_DIR}/thirdparty/linux/boost/")

set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)

find_package(Boost  COMPONENTS system thread)

if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIR}) 
  message( "Found Boost at ${Boost_LIBRARY_DIR}")
else()
   message(FATAL_ERROR "Failed to find boost at " ${Boost_Lib_Dirs} " Need system thread")
endif()



#target_link_libraries(cryptoTools sha_asm)
target_link_libraries(cryptoTools ${MIRACL_LIB})
target_link_libraries(cryptoTools ${Boost_LIBRARIES})


#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
