if(NOT DEFINED CRYPTOTOOLS_BUILD_TYPE)
	if(DEFINED CMAKE_BUILD_TYPE)
		set(CRYPTOTOOLS_BUILD_TYPE ${CMAKE_BUILD_TYPE})
	else()
		set(CRYPTOTOOLS_BUILD_TYPE "Release")
	endif()
endif()

if(NOT CRYPTOTOOLS_BUILD_DIR)
    if(MSVC)

        set(CRYPTOTOOLS_CONFIG_NAME "${CRYPTOTOOLS_BUILD_TYPE}")
        if("${CRYPTOTOOLS_CONFIG_NAME}" STREQUAL "RelWithDebInfo" )
            set(CRYPTOTOOLS_CONFIG_NAME "Release")
	    endif()


        set(CRYPTOTOOLS_BUILD_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/build/x64-${CRYPTOTOOLS_CONFIG_NAME}")
    else()
        set(CRYPTOTOOLS_BUILD_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/build/linux")

        if(NOT EXISTS "${CRYPTOTOOLS_BUILD_DIR}")
            set(CRYPTOTOOLS_BUILD_DIR "${CMAKE_CURRENT_LIST_DIR}/../")
        endif()
    endif()
else()
    if(NOT DEFINED LIBOTE_BUILD_DIR)
        message(STATUS "CRYPTOTOOLS_BUILD_DIR preset to ${CRYPTOTOOLS_BUILD_DIR}")
    endif()
endif()

if(NOT EXISTS "${CRYPTOTOOLS_BUILD_DIR}")
    message(FATAL_ERROR "failed to find the cryptoTools build directory. Looked at CRYPTOTOOLS_BUILD_DIR: ${CRYPTOTOOLS_BUILD_DIR}")
endif()