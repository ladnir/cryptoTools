include("${CMAKE_CURRENT_LIST_DIR}/cryptoToolsFindBuildDir.cmake")

if(NOT EXISTS "${cryptoTools_BIN_DIR}/CMakeCache.txt")
    message(FATAL_ERROR "cache file does not exist at ${cryptoTools_BIN_DIR}")
endif()

LOAD_CACHE("${cryptoTools_BIN_DIR}/" INCLUDE_INTERNALS 
    ENABLE_BOOST 
    ENABLE_RELIC
    )
