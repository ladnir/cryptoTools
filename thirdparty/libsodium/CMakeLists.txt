cmake_minimum_required(VERSION 3.12)

project(LIBSODIUM_DOWNLOAD VERSION 1.0.18)

include(ProcessorCount)
ProcessorCount(N)
if(NOT N EQUAL 0)
    set(PAR ${N})
else()
    set(PAR 1)
endif()

include(ExternalProject)

ExternalProject_Add(EP_LIBSODIUM
    TMP_DIR             ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR           ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR        ""
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/src
    INSTALL_DIR         ${CMAKE_INSTALL_PREFIX}
    GIT_REPOSITORY      https://github.com/osu-crypto/libsodium.git
    GIT_TAG             4e825a68baebdf058543f29762c73c17b1816ec0
    GIT_CONFIG          advice.detachedHead=false
    BUILD_IN_SOURCE     1
    UPDATE_COMMAND      ""
    PATCH_COMMAND       ""
    CONFIGURE_COMMAND   ./autogen.sh -s COMMAND ./configure --prefix=${CMAKE_INSTALL_PREFIX}
    BUILD_COMMAND       ${CMAKE_MAKE_PROGRAM} install -j${PAR}
    INSTALL_COMMAND     ""
    TEST_COMMAND        ""
)