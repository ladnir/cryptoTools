# these are just pass through config file for the ones that are placed in the build directory.


include("${CMAKE_CURRENT_LIST_DIR}/cryptoToolsFindBuildDir.cmake")
include("${CRYPTOTOOLS_BUILD_DIR}/cryptoToolsConfigVersion.cmake")
if(NOT EXISTS "${CRYPTOTOOLS_BUILD_DIR}")
    message("failed to find the cryptoTools build directory. Looked at CRYPTOTOOLS_BUILD_DIR: ${CRYPTOTOOLS_BUILD_DIR}")
    set(PACKAGE_VERSION_UNSUITABLE TRUE)
endif()

