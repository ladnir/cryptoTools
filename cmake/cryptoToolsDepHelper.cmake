include(CheckSymbolExists)
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
endif()

## Relic
###########################################################################

if (ENABLE_RELIC)

    if(NOT RLC_LIBRARY)
        if(EXISTS "${OC_THIRDPARTY_HINT}/cmake/relic-config.cmake")
            set(RELIC_ROOT ${OC_THIRDPARTY_HINT})
        endif()
      
        # does not property work on windows. Need to do a PR on relic.
        #find_package(RELIC REQUIRED HINTS "${OC_THIRDPARTY_HINT}")
      
        find_path(RLC_INCLUDE_DIR relic/relic.h HINTS  "${RELIC_ROOT}/include")
        find_library(RLC_LIBRARY NAMES relic relic_s  HINTS "${RELIC_ROOT}/lib")

        include (FindPackageHandleStandardArgs)
        find_package_handle_standard_args(RELIC DEFAULT_MSG RLC_INCLUDE_DIR RLC_LIBRARY)

        if(RLC_FOUND)
            set(RLC_LIBRARIES ${RLC_LIBRARY})
            set(RLC_INCLUDE_DIRS ${RLC_INCLUDE_DIR})
        endif()
    endif()


    if(NOT DEFINED RLC_LIBRARY)
        set(RLC_LIBRARY "${RELIC_LIBRARIES}${RLC_LIBRARY}")
        set(RLC_INCLUDE_DIR "${RELIC_INCLUDE_DIR}${RLC_INCLUDE_DIR}")
    endif()

    message(STATUS "Relic_LIB:  ${RLC_LIBRARY}")
    message(STATUS "Relic_inc:  ${RLC_INCLUDE_DIR}\n")


endif (ENABLE_RELIC)


# libsodium
###########################################################################

if (ENABLE_SODIUM)
  pkg_check_modules(SODIUM REQUIRED libsodium)

  if (NOT SODIUM_FOUND)
    message(FATAL_ERROR "Failed to find libsodium")
  endif (NOT SODIUM_FOUND)

  message(STATUS "SODIUM_INCLUDE_DIRS:  ${SODIUM_INCLUDE_DIRS}")
  message(STATUS "SODIUM_LIBRARY_DIRS:  ${SODIUM_LIBRARY_DIRS}")
  message(STATUS "SODIUM_LIBRARIES:  ${SODIUM_LIBRARIES}\n")

  set(CMAKE_REQUIRED_INCLUDES ${SODIUM_INCLUDE_DIRS})
  set(CMAKE_REQUIRED_LINK_OPTIONS ${SODIUM_LDFLAGS})
  set(CMAKE_REQUIRED_LIBRARIES ${SODIUM_LIBRARIES})
  check_symbol_exists(crypto_scalarmult_noclamp "sodium.h" SODIUM_MONTGOMERY)
  unset(CMAKE_REQUIRED_LIBRARIES)
  unset(CMAKE_REQUIRED_LINK_OPTIONS)
  unset(CMAKE_REQUIRED_INCLUDES)

  if (SODIUM_MONTGOMERY)
    message(STATUS "Sodium supports Montgomery curve noclamp operations.")
  else()
    message(STATUS "Sodium does not support Montgomery curve noclamp operations.")
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

    #set(OC_BOOST_SEARCH_PATHS "${BOOST_ROOT}")
    if(NOT BOOST_ROOT)
        set(BOOST_ROOT ${OC_THIRDPARTY_HINT})
    #    if(MSVC)
    #        set(OC_BOOST_ROOT_local "${CMAKE_CURRENT_LIST_DIR}/../#thirdparty/boost/")
    #        #set(OC_BOOST_ROOT_install "c:/libs/boost/")
    #        #message("\n\n\n\nhere 1 >${OC_BOOST_ROOT_install}<\n\n\n")
    #
    #        set(OC_BOOST_SEARCH_PATHS "${OC_BOOST_SEARCH_PATHS} #${OC_BOOST_ROOT_local} ${OC_BOOST_ROOT_install}")
    #
    #        if(EXISTS "${OC_BOOST_ROOT_local}")
    #            set(BOOST_ROOT "${OC_BOOST_ROOT_local}")
    #            message("\n\n\n\nhere ${BOOST_ROOT}\n\n\n\n")
    #        else()
    #            #set(BOOST_ROOT "${OC_BOOST_ROOT_install}")
    #            #message("\n\n\n\nhere 2 >${BOOST_ROOT}<\n\n\n\n")
    #        endif()
    #    else()
    #        set(BOOST_ROOT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/#boost/")
    #    endif()
    endif()



    if(MSVC)
        set(Boost_LIB_PREFIX "lib")
    endif()

    #set(Boost_USE_STATIC_LIBS        ON) # only find static libs
    set(Boost_USE_MULTITHREADED      ON)
    #set(Boost_USE_STATIC_RUNTIME     OFF)
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
