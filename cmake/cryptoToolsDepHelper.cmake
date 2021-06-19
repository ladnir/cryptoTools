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

    if(MSVC)
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/win/")
    else()
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/unix/")
    endif()

    if(NOT EXISTS ${OC_THIRDPARTY_HINT})
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../../..")
    endif()
endif()

set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};${OC_THIRDPARTY_HINT}")


## Relic
###########################################################################

include (FindPackageHandleStandardArgs)
if (ENABLE_RELIC)

    if(NOT DEFINED RELIC_ROOT)
        set(RELIC_ROOT ${OC_THIRDPARTY_HINT})
    endif()
      
    # does not property work on windows. Need to do a PR on relic.
    #find_package(RELIC REQUIRED HINTS "${OC_THIRDPARTY_HINT}")
      
    find_path(RLC_INCLUDE_DIR "relic/relic.h" HINTS  "${RELIC_ROOT}" PATH_SUFFIXES "/include/")
    find_library(RLC_LIBRARY NAMES relic relic_s  HINTS "${RELIC_ROOT}" PATH_SUFFIXES "/lib/")

    find_package_handle_standard_args(RELIC DEFAULT_MSG RLC_INCLUDE_DIR RLC_LIBRARY)

    if(RLC_FOUND)
        set(RLC_LIBRARIES ${RLC_LIBRARY})
        set(RLC_INCLUDE_DIRS ${RLC_INCLUDE_DIR})
    endif()

        
    add_library(relic STATIC IMPORTED)
    
    set_property(TARGET relic PROPERTY IMPORTED_LOCATION ${RLC_LIBRARY})
    target_include_directories(relic INTERFACE 
                    $<BUILD_INTERFACE:${RLC_INCLUDE_DIR}>
                    $<INSTALL_INTERFACE:>)
    
    
    if(NOT EXISTS ${RLC_INCLUDE_DIR} OR NOT  EXISTS ${RLC_LIBRARY})
        message(FATAL_ERROR "could not find relic.\n\nRLC_LIBRARY=${RLC_LIBRARY}\nRLC_INCLUDE_DIR=${RLC_INCLUDE_DIR}\n Looked at RELIC_ROOT=${RELIC_ROOT}; and system installs.\n OC_THIRDPARTY_HINT=${OC_THIRDPARTY_HINT}\n")
    endif()
    message(STATUS "Relic_LIB:  ${RLC_LIBRARY}")
    message(STATUS "Relic_inc:  ${RLC_INCLUDE_DIR}\n")


endif (ENABLE_RELIC)

# libsodium
###########################################################################

if (ENABLE_SODIUM)
  
    find_path(SODIUM_INCLUDE_DIRS sodium.h HINTS  "${OC_THIRDPARTY_HINT}/include")
    find_library(SODIUM_LIBRARIES NAMES sodium libsodium HINTS "${OC_THIRDPARTY_HINT}/lib")

    if (NOT SODIUM_INCLUDE_DIRS OR NOT SODIUM_LIBRARIES)
        message(FATAL_ERROR "Failed to find libsodium.\n  OC_THIRDPARTY_HINT=${OC_THIRDPARTY_HINT}\n  SODIUM_INCLUDE_DIRS=${SODIUM_INCLUDE_DIRS}\n  SODIUM_LIBRARIES=${SODIUM_LIBRARIES}")
    endif ()
    
    set(SODIUM_MONTGOMERY ON CACHE BOOL "SODIUM_MONTGOMERY...")

    message(STATUS "SODIUM_INCLUDE_DIRS:  ${SODIUM_INCLUDE_DIRS}")
    message(STATUS "SODIUM_LIBRARIES:  ${SODIUM_LIBRARIES}")
    message(STATUS "SODIUM_MONTGOMERY:  ${SODIUM_MONTGOMERY}\n")

    add_library(sodium STATIC IMPORTED)
    
    set_property(TARGET sodium PROPERTY IMPORTED_LOCATION ${SODIUM_LIBRARIES})
    target_include_directories(sodium INTERFACE 
                    $<BUILD_INTERFACE:${SODIUM_INCLUDE_DIRS}>
                    $<INSTALL_INTERFACE:>)

    if(MSVC)
        target_compile_definitions(sodium INTERFACE SODIUM_STATIC=1)
    endif()
endif (ENABLE_SODIUM)


## WolfSSL
###########################################################################

if(ENABLE_WOLFSSL)

  if(NOT DEFINED WolfSSL_DIR)
    set(WolfSSL_DIR "/usr/local/")
  endif()


  find_library(WOLFSSL_LIB NAMES wolfssl  HINTS "${WolfSSL_DIR}")
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

    set(Boost_USE_MULTITHREADED      ON)
    #set (Boost_DEBUG ON)  #<---------- Real life saver
    #message("BOOST_ROOT=${BOOST_ROOT}")

    macro(findBoost)
        if(MSVC)
            find_package(Boost 1.75 COMPONENTS system thread regex)
        else()
            find_package(Boost 1.75 COMPONENTS system thread)
        endif()
    endmacro()

    # then look at system dirs
    if(NOT Boost_FOUND)
        findBoost()
    endif()

    if(NOT Boost_FOUND)
        message(FATAL_ERROR "Failed to find boost 1.75+ at \"${BOOST_ROOT}\" or at system install")
    endif()

    message(STATUS "Boost_LIB: ${Boost_LIBRARIES}" )
    message(STATUS "Boost_INC: ${Boost_INCLUDE_DIR}\n\n" )

endif()


# resort the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
cmake_policy(POP)