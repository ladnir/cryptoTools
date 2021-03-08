## Relic
###########################################################################

if (ENABLE_RELIC)

  if(NOT RLC_LIBRARY)
      if(MSVC)
            if(NOT RLC_INCLUDE_DIR)
                set(RLC_INCLUDE_DIR "c:/libs/include")
                set(RLC_LIBRARY "c:/libs/lib/relic_s.lib")
            endif()
        
          if (NOT EXISTS "${RLC_INCLUDE_DIR}/relic")
            message(FATAL_ERROR "Failed to find Relic at ${RLC_INCLUDE_DIR}/relic. Please set RLC_INCLUDE_DIR and RLC_LIBRARY manually.")
          endif (NOT Relic_FOUND)
      else()
          find_package(Relic REQUIRED)

          if (NOT Relic_FOUND)
            message(FATAL_ERROR "Failed to find Relic")
          endif (NOT Relic_FOUND)
      endif()
  endif()
  set(RLC_LIBRARY "${RELIC_LIBRARIES}${RLC_LIBRARY}")
  set(RLC_INCLUDE_DIR "${RELIC_INCLUDE_DIR}${RLC_INCLUDE_DIR}")

  message(STATUS "Relic_LIB:  ${RLC_LIBRARY}")
  message(STATUS "Relic_inc:  ${RLC_INCLUDE_DIR}\n")


endif (ENABLE_RELIC)




## WolfSSL
###########################################################################

if(ENABLE_WOLFSSL)

  if(NOT DEFINED WolfSSL_DIR)
    set(WolfSSL_DIR "/usr/local/")
  endif()
  

  find_library(WOLFSSL_LIB NAMES wolfssl  HINTS "${WolfSSL_DIR}")
  set(WOLFSSL_LIB_INCLUDE_DIRS "${WolfSSL_DIR}include/")
  
  # if we cant fint it, throw an error
  if(NOT WOLFSSL_LIB)
      message(FATAL_ERROR "Failed to find WolfSSL at " ${WolfSSL_DIR})
  endif()

  message(STATUS "WOLFSSL_LIB:  ${WOLFSSL_LIB}")
  message(STATUS "WOLFSSL_INC:  ${WOLFSSL_LIB_INCLUDE_DIRS}\n")
  
endif(ENABLE_WOLFSSL)


## Boost
###########################################################################



if(ENABLE_BOOST)
    
    set(BOOST_SEARCH_PATHS "${BOOST_ROOT}")

    if(NOT BOOST_ROOT OR NOT EXISTS "${BOOST_ROOT}")
        if(MSVC)
            set(BOOST_ROOT_local "${CMAKE_CURRENT_LIST_DIR}/../cryptoTools/thirdparty/win/boost/")
            set(BOOST_ROOT_install "c:/libs/boost/")
            

            set(BOOST_SEARCH_PATHS "${BOOST_SEARCH_PATHS} ${BOOST_ROOT_local} ${BOOST_ROOT_install}")

            if(EXISTS "${BOOST_ROOT_local}")
                set(BOOST_ROOT "${BOOST_ROOT_local}")
            else()
                set(BOOST_ROOT "${BOOST_ROOT_install}")
            endif()
        else()
            set(BOOST_ROOT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/linux/boost/")
        
            set(BOOST_SEARCH_PATHS "${BOOST_SEARCH_PATHS} ${BOOST_ROOT}")
        endif()
    endif()


    if(MSVC)
        set(Boost_LIB_PREFIX "lib")
    endif()

    #set(Boost_USE_STATIC_LIBS        ON) # only find static libs
    set(Boost_USE_MULTITHREADED      ON)
    #set(Boost_USE_STATIC_RUNTIME     OFF)
    #set (Boost_DEBUG ON)  #<---------- Real life saver

    macro(findBoost)
        if(MSVC)
            find_package(Boost 1.69 COMPONENTS system thread regex)
        else()
            find_package(Boost 1.69 COMPONENTS system thread)
        endif()
    endmacro()

    # then look at system dirs
    if(NOT Boost_FOUND)
        findBoost()
    endif()

    if(NOT Boost_FOUND)
        message(FATAL_ERROR "Failed to find boost 1.69+ at ${BOOST_SEARCH_PATHS} or at system install")
    endif()

    message(STATUS "Boost_LIB: ${Boost_LIBRARIES}" )
    message(STATUS "Boost_INC: ${Boost_INCLUDE_DIR}\n\n" )
    
endif()
