
set(GIT_REPOSITORY      https://github.com/relic-toolkit/relic.git )
set(GIT_TAG             "0.6.0" )

set(CLONE_DIR "${CMAKE_CURRENT_LIST_DIR}/relic")
set(BUILD_DIR "${CLONE_DIR}/build/${OC_CONFIG}")
set(CONFIG    --config Release)
set(LOG_FILE  "${CMAKE_CURRENT_LIST_DIR}/log-relic.txt")

if(MSVC)
    set(MP_ARG "-DMULTI:STRING=OPENMP")
else()
    set(MP_ARG "-DMULTI:STRING=PTHREAD")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/fetch.cmake")

if(NOT EXISTS ${BUILD_DIR} OR NOT RELIC_FOUND)
    find_program(GIT git REQUIRED)
    set(DOWNLOAD_CMD  ${GIT} clone ${GIT_REPOSITORY})
    set(CHECKOUT_CMD  ${GIT} checkout ${GIT_TAG})
    set(CONFIGURE_CMD ${CMAKE_COMMAND} -S ${CLONE_DIR} -B ${BUILD_DIR} -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
                       -DCMAKE_BUILD_TYPE:STRING=Release
                       ${MP_ARG})
    set(BUILD_CMD     ${CMAKE_COMMAND} --build ${BUILD_DIR} ${CONFIG})
    set(INSTALL_CMD   ${CMAKE_COMMAND} --install ${BUILD_DIR} ${CONFIG} --prefix ${OC_THIRDPARTY_INSTALL_PREFIX})


    message("============= Building Relic =============")
    if(NOT EXISTS ${CLONE_DIR})
        run(NAME "Cloning ${GIT_REPOSITORY}" CMD ${DOWNLOAD_CMD} WD ${CMAKE_CURRENT_LIST_DIR})
    endif()

    run(NAME "Checkout ${GIT_TAG} " CMD ${CHECKOUT_CMD}  WD ${CLONE_DIR})
    run(NAME "Configure"       CMD ${CONFIGURE_CMD} WD ${CLONE_DIR})
    run(NAME "Build"           CMD ${BUILD_CMD}     WD ${CLONE_DIR})
    run(NAME "Install"         CMD ${INSTALL_CMD}   WD ${CLONE_DIR})

    message("log ${LOG_FILE}\n==========================================")
else()
    message("relic already fetched.")
endif()

install(CODE "
    execute_process(
        COMMAND ${SUDO} \${CMAKE_COMMAND} --install \"${BUILD_DIR}\" ${CONFIG} --prefix \${CMAKE_INSTALL_PREFIX}
        WORKING_DIRECTORY ${CLONE_DIR}
        RESULT_VARIABLE RESULT
        COMMAND_ECHO STDOUT
    )
")