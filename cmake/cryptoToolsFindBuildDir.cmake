
if(MSVC)
    set(OC_CONFIG "x64-${CMAKE_BUILD_TYPE}")
elseif(APPLE)
    set(OC_CONFIG "osx")
else()
    set(OC_CONFIG "linux")
endif()


if(NOT CRYPTOTOOLS_BUILD_DIR)
    set(CRYPTOTOOLS_BUILD_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/build/${OC_CONFIG}")
else()
    if(NOT DEFINED LIBOTE_BUILD_DIR)
        message(STATUS "CRYPTOTOOLS_BUILD_DIR preset to ${CRYPTOTOOLS_BUILD_DIR}")
    endif()
endif()

if(NOT EXISTS "${CRYPTOTOOLS_BUILD_DIR}")
    message(FATAL_ERROR "failed to find the cryptoTools build directory. Looked at CRYPTOTOOLS_BUILD_DIR: ${CRYPTOTOOLS_BUILD_DIR}")
endif()