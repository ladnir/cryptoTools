

set(GIT_REPOSITORY      https://github.com/osu-crypto/libsodium.git)
set(GIT_TAG             "4e825a68baebdf058543f29762c73c17b1816ec0" )

set(CLONE_DIR "${OC_THIRDPARTY_CLONE_DIR}/libsodium")
set(BUILD_DIR "${CLONE_DIR}/build/${OC_CONFIG}")
set(LOG_FILE  "${CMAKE_CURRENT_LIST_DIR}/log-libsodium.txt")

include("${CMAKE_CURRENT_LIST_DIR}/fetch.cmake")

find_program(GIT git REQUIRED)
set(DOWNLOAD_CMD  ${GIT} clone ${GIT_REPOSITORY})
set(CHECKOUT_CMD  ${GIT} checkout ${GIT_TAG})


if(NOT SODIUM_FOUND)
    message("============= Building Sodium =============")

    if(NOT EXISTS ${CLONE_DIR})
        run(NAME "Cloning ${GIT_REPOSITORY}" CMD ${DOWNLOAD_CMD} WD ${OC_THIRDPARTY_CLONE_DIR})
    endif()
    run(NAME "Checkout ${GIT_TAG} " CMD ${CHECKOUT_CMD}  WD ${CLONE_DIR})

    if(MSVC)
        # delete the post build tests
        file(WRITE ${CLONE_DIR}/test/default/wintest.bat "")
        vsrun(NAME "build-sodium" CMD
            "MSBuild.exe ./libsodium.sln -t:libsodium -p:Configuration=Release /p:PlatformToolset=v${MSVC_TOOLSET_VERSION} /p:Platform=x64\n"
            "mkdir ${OC_THIRDPARTY_INSTALL_PREFIX}/include/ -Force\n"
            "mkdir ${OC_THIRDPARTY_INSTALL_PREFIX}/lib/ -Force\n"
            "cp ./src/libsodium/include/* ${OC_THIRDPARTY_INSTALL_PREFIX}/include/ -Recurse -Force\n"
            "cp ./Build/Release/x64/libsodium.lib ${OC_THIRDPARTY_INSTALL_PREFIX}/lib/ -Force\n"
            "mkdir ${OC_THIRDPARTY_INSTALL_PREFIX}/lib/cmake/libsodium/ -Force\n"
            WD ${CLONE_DIR}
            )

        if(NOT EXISTS "${CLONE_DIR}/Build/Release/x64/libsodium.lib")
            message(FATAL_ERROR "Sodium failed to build. See ${LOG_FILE}")
        endif()
    else()

        ## in case this is hosted in WSL
        find_program(DOS2UNIX dos2unix)
        if(DOS2UNIX)
            set(DOS2UNIX_CMD bash -c "find . \\( -name \"*.m4\" -o -name \"*.ac\" -o -name \"*.am\" \\) | xargs ${DOS2UNIX}")
            run(NAME "dos2unix" CMD ${DOS2UNIX_CMD} WD ${CLONE_DIR})
        endif()
        
        #find_program(AUTOGEN autogen)
        #if(NOT AUTOGEN)
        #    message(FATAL_ERROR "program autogen must be installed.")
        #endif()
        #find_program(LIBTOOL libtool)
        #if(NOT LIBTOOL)
        #    message(FATAL_ERROR "program libtool must be installed.")
        #endif()

        if(ENABLE_PIC)
            set(WITH_PIC "--with-pic=yes")
        else()
            set(WITH_PIC "--with-pic=no")
        endif()

    
        set(AUTOGEN_CMD "./autogen.sh" "-s")
        set(CONFIGURE_CMD "./configure" "--prefix=${OC_THIRDPARTY_INSTALL_PREFIX}" ${WITH_PIC})
        set(BUILD_CMD     "make" "-j" "${PARALLEL_FETCH}")
        set(INSTALL_CMD   ${SUDO} "make" "install")

        if(NOT EXISTS ${CLONE_DIR})
            run(NAME "Cloning ${GIT_REPOSITORY}" CMD ${DOWNLOAD_CMD} WD ${CMAKE_CURRENT_LIST_DIR})
        endif()

        run(NAME "Autogen"         CMD ${AUTOGEN_CMD} WD ${CLONE_DIR})
        run(NAME "Configure"       CMD ${CONFIGURE_CMD} WD ${CLONE_DIR})
        run(NAME "Build"           CMD ${BUILD_CMD}     WD ${CLONE_DIR})
        run(NAME "Install"         CMD ${INSTALL_CMD}   WD ${CLONE_DIR})
        run(NAME "Install2"        CMD "mkdir" "-p"  "${OC_THIRDPARTY_INSTALL_PREFIX}/lib/cmake/libsodium" WD ${CLONE_DIR})
    endif()
    
    file(WRITE ${OC_THIRDPARTY_INSTALL_PREFIX}/lib/cmake/libsodium/libsodiumConfig.cmake "set(libsodium_pic ${ENABLE_PIC})")
    message("log ${LOG_FILE}\n==========================================")

else()
        message("sodium already fetched.")
endif()


if(MSVC)
    install(
        DIRECTORY "${CLONE_DIR}/src/libsodium/include/"
        DESTINATION "include"
        FILES_MATCHING PATTERN "*.h")
    install(
        FILES "${CLONE_DIR}/Build/Release/x64/libsodium.lib"
        DESTINATION "lib")
else()
    install(CODE "
    
        if(NOT CMAKE_INSTALL_PREFIX STREQUAL \"${OC_THIRDPARTY_INSTALL_PREFIX}\")
            execute_process(
                COMMAND ${SUDO} mkdir -p \${CMAKE_INSTALL_PREFIX}/lib/cmake/libsodium
                COMMAND ${SUDO} mkdir -p \${CMAKE_INSTALL_PREFIX}/include/sodium
                COMMAND ${SUDO} cp ${OC_THIRDPARTY_INSTALL_PREFIX}/lib/libsodium.a \${CMAKE_INSTALL_PREFIX}/lib/
                COMMAND ${SUDO} cp -r ${OC_THIRDPARTY_INSTALL_PREFIX}/lib/cmake/libsodium/libsodiumConfig.cmake \${CMAKE_INSTALL_PREFIX}/lib/cmake/libsodium/
                COMMAND ${SUDO} cp ${OC_THIRDPARTY_INSTALL_PREFIX}/include/sodium.h \${CMAKE_INSTALL_PREFIX}/include/
                COMMAND ${SUDO} cp -r ${OC_THIRDPARTY_INSTALL_PREFIX}/include/sodium \${CMAKE_INSTALL_PREFIX}/include/
                WORKING_DIRECTORY \"${CLONE_DIR}\"
                RESULT_VARIABLE RESULT
                COMMAND_ECHO STDOUT
            )
        endif()
    ")
endif()