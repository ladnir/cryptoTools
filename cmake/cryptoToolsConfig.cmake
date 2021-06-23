# these are just pass through config file for the ones that are placed in the build directory.

if(MSVC)
    set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/win/")
else()
    set(OC_THIRDPARTY_HINT "${CMAKE_CURRENT_LIST_DIR}/../thirdparty/unix/")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/cryptoToolsFindBuildDir.cmake")
include("${CRYPTOTOOLS_BUILD_DIR}/cryptoToolsConfig.cmake")

