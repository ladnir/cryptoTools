project(cryptoTools)

get_directory_property(hasParent PARENT_DIRECTORY)


find_program(NASM nasm)


if(NOT NASM OR NOT ("$ENV{cryptoTools_NO_NASM}" STREQUAL ""))
  message(WARNING "\nnasm is not in the PATH or cryptoTools_NO_NASM is defined!!!! This means the fast SHA1 function will not be used.")
  MESSAGE(STATUS "ENV{cryptoTools_NO_NASM} = $ENV{cryptoTools_NO_NASM}")

  # define this so that the asm is disabled.
  add_definitions(-DNO_INTEL_ASM_SHA1=1)
  set(shaNasmOutput )
  add_custom_target(sha_asm)
  
else()
  
    set(shaNasm "${CMAKE_CURRENT_SOURCE_DIR}/Crypto/asm/sha_lnx.S")
    set(shaNasmOutput "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/cryptoTools.dir/Crypto/sha_lnx.S.o")

    #Default nasm flags
    set(shaNasmComment ${NASM} -f elf64 ${shaNasm} -o ${shaNasmOutput})
    set(shaNasmCommand ${NASM} -f elf64 ${shaNasm} -o ${shaNasmOutput})

    #OSX nasm flags
    IF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(shaNasmComment ${NASM} --prefix _ -f macho64 ${shaNasm} -o ${shaNasmOutput})
    set(shaNasmCommand ${NASM} --prefix _ -f macho64 ${shaNasm} -o ${shaNasmOutput})
    ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

    add_custom_command(
            OUTPUT ${shaNasmOutput}
            DEPENDS ${shaNasm} 
            COMMENT ${shaNasmComment}
            COMMAND ${shaNasmCommand}
            VERBATIM)

  # mark this asm output input to everything.
  add_custom_target(sha_asm DEPENDS ${shaNasmOutput})
endif()



# add the source files 
file(GLOB_RECURSE SRCS *.cpp)
add_library(cryptoTools STATIC ${SRCS} ${shaNasmOutput})

# make projects that include cryptoTools use this as an include folder
target_include_directories(cryptoTools PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/..")
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


## Miracl
###########################################################################

set(Miracl_Dirs "${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/linux/miracl/")

set(Miracl_Lib_Dirs "${Miracl_Dirs}/miracl/source/")
find_library(MIRACL_LIB NAMES miracl  HINTS "${Miracl_Lib_Dirs}")

# if we cant fint it, throw an error
if(NOT MIRACL_LIB)
    message(FATAL_ERROR "Failed to find miracl at " ${Miracl_Lib_Dirs})
endif()
message(STATUS "MIRACL_LIB:  ${MIRACL_LIB}")

#include_directories("${Miracl_Dirs}") 

target_include_directories(cryptoTools PUBLIC "${Miracl_Dirs}") 
target_link_libraries(cryptoTools ${MIRACL_LIB})


INSTALL(DIRECTORY "${Miracl_Dirs}/miracl/include/" DESTINATION include)
INSTALL(FILES ${MIRACL_LIB} DESTINATION lib)

#copy miracl to the lib directory for others to use/find
#file(COPY ${MIRACL_LIB}  DESTINATION ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})
#file(GLOB_RECURSE miracl_headers "${Miracl_Dirs}/miracl/include/*.h")
#file(COPY ${miracl_headers}  DESTINATION "${CMAKE_SOURCE_DIR}/include/")
#MESSAGE(STATUS  " headers ${miracl_headers}")

## Boost
###########################################################################

set(BOOST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/linux/boost/")

set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)

find_package(Boost COMPONENTS system thread)

if(NOT Boost_FOUND)
    message(FATAL_ERROR "Failed to find boost at " ${Boost_Lib_Dirs} " Need system thread")
endif()


#MESSAGE(STATUS "boost ---  ${Boost_LIBRARIES}")
#include_directories(${Boost_INCLUDE_DIR}) 

target_include_directories(cryptoTools PUBLIC ${Boost_INCLUDE_DIR}) 
target_link_libraries(cryptoTools ${Boost_LIBRARIES})


IF(INSTALL_BOOST)
    INSTALL(DIRECTORY "${Boost_INCLUDE_DIR}/boost" DESTINATION include)
    INSTALL(FILES ${Boost_LIBRARIES} DESTINATION lib)
ENDIF(INSTALL_BOOST)

#file(COPY ${Boost_LIBRARIES}  DESTINATION ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})
#FILE(COPY "${Boost_INCLUDE_DIR}/boost" DESTINATION "${CMAKE_SOURCE_DIR}/include/boost")
message(STATUS "Boost_include  ${Boost_INCLUDE_DIR}" )
