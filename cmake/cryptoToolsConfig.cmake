# these are just pass through config file for the ones that are placed in the build directory.
if(NOT DEFINED OC_THIRDPARTY_HINT)
    if(MSVC)
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../cryptoTools/thirdparty/win/")
    else()
        set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../cryptoTools/thirdparty/unix/")
    endif()
endif()

include("${CMAKE_CURRENT_LIST_DIR}/cryptoToolsFindBuildDir.cmake")
include("${CRYPTOTOOLS_BUILD_DIR}/cryptoToolsConfig.cmake")

