project(cryptoTools)

set(BUILD_CURVE ON CACHE BOOL "whether to build Curve.cpp- requires miracl")


get_directory_property(hasParent PARENT_DIRECTORY)



if($ENV{nasm} MATCHES "")
	message(WARNING "\nnasm environment variable NOT defined!!!! This means the fast SHA1 function will not be used.")

	# define this so that the asm is disabled.
	add_definitions(-DNO_INTEL_ASM_SHA1=1)
	set(shaNasmOutput )
	add_custom_target(sha_asm)
	
else()
        set(shaNasm "${CMAKE_CURRENT_SOURCE_DIR}/Crypto/asm/sha_lnx.S")
        set(shaNasmOutput "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/cryptoTools.dir/Crypto/sha_lnx.S.o")
      
        add_custom_command(
                OUTPUT ${shaNasmOutput}
                DEPENDS ${shaNasm} 
                COMMENT "nasm -f elf64 ${shaNasm} -o ${shaNasmOutput}"
                COMMAND "nasm" "-f elf64" "${shaNasm}" "-o ${shaNasmOutput}"
                VERBATIM)


	# mark this asm output input to everything.
	add_custom_target(sha_asm DEPENDS ${shaNasmOutput})
endif()


file(GLOB_RECURSE SRCS *.cpp)

if (NOT ${BUILD_CURVE})
    list(REMOVE_ITEM SRCS ${CMAKE_CURRENT_SOURCE_DIR}/Crypto/Curve.cpp)
endif()

add_library(cryptoTools STATIC ${SRCS} ${shaNasmOutput})
add_dependencies(cryptoTools sha_asm)

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
  
if (${BUILD_CURVE})

	set(Miracl_Lib_Dirs "${Miracl_Dirs}/miracl/source/")
    find_library(MIRACL_LIB NAMES miracl  HINTS "${Miracl_Lib_Dirs}")
    # if we cant fint it, throw an error
    if(NOT MIRACL_LIB)
        Message(${MIRACL_LIB})
        message(FATAL_ERROR "Failed to find miracl at " ${Miracl_Lib_Dirs})
    endif()
	
	
	message(WARNING "Miracl_Dirs: ${Miracl_Dirs}")
	message(WARNING "MIRACL_LIB:  ${MIRACL_LIB}")
endif()

set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)

find_package(Boost COMPONENTS system thread)

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIR}) 
else()
    message(FATAL_ERROR "Failed to find boost at " ${Boost_Lib_Dirs} " Need system thread")
endif()

if (${BUILD_CURVE})
    target_link_libraries(cryptoTools ${MIRACL_LIB})
endif()

target_link_libraries(cryptoTools ${Boost_LIBRARIES})
