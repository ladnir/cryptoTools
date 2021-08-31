cmake_minimum_required(VERSION 3.12)

project(RELIC_DOWNLOAD VERSION 0.5.0)

include(ExternalProject)

if(WIN32)
    set(MP_ARG "-DMULTI:STRING=OPENMP")
else()
    set(MP_ARG "-DMULTI:STRING=PTHREAD")
endif()

ExternalProject_Add(EP_RELIC
    TMP_DIR             ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR           ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR        ""
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    BINARY_DIR          ${CMAKE_CURRENT_LIST_DIR}/build
    INSTALL_DIR         ${CMAKE_INSTALL_PREFIX}
    GIT_REPOSITORY      https://github.com/relic-toolkit/relic.git
    GIT_TAG             3f616ad64c3e63039277b8c90915607b6a2c504c
    GIT_CONFIG          advice.detachedHead=false
    CMAKE_ARGS          -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
    CMAKE_CACHE_ARGS    -DCMAKE_BUILD_TYPE:STRING=Release
                        -DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=ON
                        "${MP_ARG}"
    TEST_COMMAND        ""
)