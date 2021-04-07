

if(NOT cryptoTools_BIN_DIR)
    if(MSVC)

        if(NOT CMAKE_BUILD_TYPE)
            message(FATAL_ERROR "can not locate cryptoTools binary dir due to CMAKE_BUILD_TYPE not being set")
        endif()

        set(CONFIG_NAME "${CMAKE_BUILD_TYPE}")
        if("${CONFIG_NAME}" STREQUAL "RelWithDebInfo" )
            set(CONFIG_NAME "Release")
	    endif()


        set(cryptoTools_BIN_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/build/x64-${CONFIG_NAME}")
    else()
        set(cryptoTools_BIN_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/build/linux")

        if(NOT EXISTS "${cryptoTools_BIN_DIR}")
            set(cryptoTools_BIN_DIR "${CMAKE_CURRENT_LIST_DIR}/../")
        endif()
    endif()
else()
    message(STATUS "cryptoTools_BIN_DIR preset to ${cryptoTools_BIN_DIR}")
endif()

if(NOT EXISTS "${cryptoTools_BIN_DIR}")
    message(FATAL_ERROR "failed to find the cryptoTools build directory. Looked at: ${cryptoTools_BIN_DIR}")
endif()