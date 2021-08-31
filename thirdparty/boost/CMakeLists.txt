cmake_minimum_required(VERSION 3.12)

project(BOOST_DOWNLOAD VERSION 1.75.0)

include(ProcessorCount)
ProcessorCount(N)
if(NOT N EQUAL 0)
    set(PAR ${N})
else()
    set(PAR 1)
endif()

include(ExternalProject)

if(WIN32)
    set(Boost_bootstrap_cmd bootstrap.bat)
    set(Boost_b2_cmd b2.exe)
    list(APPEND Boost_b2_args
        "-j${PAR}"
        "--prefix=${CMAKE_INSTALL_PREFIX}"
        --with-thread
        --with-system
        --with-filesystem
        --with-regex
        --with-date_time)
    list(APPEND Boost_b2_props toolset=msvc-14.2 architecture=x86 address-model=64 link=static variant=release)
    if(Boost_USE_MULTITHREADED)
        list(APPEND Boost_USE_MULTITHREADED threading=multi)
    else()
        list(APPEND Boost_USE_MULTITHREADED threading=single)
    endif()
else()
    set(Boost_bootstrap_cmd ./bootstrap.sh)
    set(Boost_b2_cmd ./b2)
    list(APPEND Boost_b2_args
        "-j${PAR}"
        "--prefix=${CMAKE_INSTALL_PREFIX}"
        --with-system
        --with-thread
        --with-filesystem
        --with-atomic
        --with-regex)
    list(APPEND Boost_b2_props variant=release)
    if(Boost_USE_MULTITHREADED)
        list(APPEND Boost_USE_MULTITHREADED threading=multi)
    else()
        list(APPEND Boost_USE_MULTITHREADED threading=single)
    endif()
endif()

ExternalProject_Add(EP_BOOST
    TMP_DIR           ${CMAKE_CURRENT_LIST_DIR}/tmp
    STAMP_DIR         ${CMAKE_CURRENT_LIST_DIR}/stamp
    DOWNLOAD_DIR      ""
    SOURCE_DIR        ${CMAKE_CURRENT_LIST_DIR}/src
    INSTALL_DIR       ${CMAKE_INSTALL_PREFIX}
    URL               https://boostorg.jfrog.io/artifactory/main/release/${PROJECT_VERSION}/source/boost_${PROJECT_VERSION_MAJOR}_${PROJECT_VERSION_MINOR}_${PROJECT_VERSION_PATCH}.tar.bz2
    URL_HASH          SHA256=953db31e016db7bb207f11432bef7df100516eeb746843fa0486a222e3fd49cb
    BUILD_IN_SOURCE   1
    UPDATE_COMMAND    ""
    PATCH_COMMAND     ""
    CONFIGURE_COMMAND ${Boost_bootstrap_cmd}
    BUILD_COMMAND     ${Boost_b2_cmd} ${Boost_b2_args} ${Boost_b2_props} install
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
)
