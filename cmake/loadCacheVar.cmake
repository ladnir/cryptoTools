include("${CMAKE_CURRENT_LIST_DIR}/cryptoToolsFindBuildDir.cmake")


LOAD_CACHE("${cryptoTools_BIN_DIR}/" INCLUDE_INTERNALS 
    ENABLE_BOOST 
    ENABLE_RELIC
    )

