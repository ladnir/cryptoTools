
    if(VERBOSE_FETCH)
        unset(RUN_OUTPUT_TYPE)
    else()
        set(RUN_OUTPUT_TYPE OUTPUT_QUIET)
    endif()

function(RUN)
    cmake_parse_arguments(
        PARSED_ARGS # prefix of parameters
        "" # list of names of the boolean arguments (only defined ones will be true)
        "WD" # list of names of mono-valued arguments
        "CMD;NAME" # list of names of multi-valued arguments (output variables are lists)
        ${ARGN} # arguments of the function to parse, here we take the all original ones
    )
    message("${PARSED_ARGS_NAME}")
    file(APPEND ${LOG_FILE}
        "############# ${PARSED_ARGS_NAME} ###########"
        "${PARSED_ARGS_CMD}"
        "#############################################"
    )


    execute_process(
        COMMAND ${PARSED_ARGS_CMD}
        WORKING_DIRECTORY ${PARSED_ARGS_WD}
        RESULT_VARIABLE RESULT
        COMMAND_ECHO STDOUT
        OUTPUT_FILE ${LOG_FILE}
        ERROR_FILE ${LOG_FILE}
        ${RUN_OUTPUT_TYPE}
    )
    if(RESULT)
        file(READ ${LOG_FILE} LOG_STRING)
        message(FATAL_ERROR "${PARSED_ARGS_NAME} failed (${RESULT}).\nLOG:\n${LOG_STRING}")
    endif()
endfunction()

set(FINDVS_PATH ${CMAKE_CURRENT_LIST_DIR}/findvs.ps1)

file(READ ${FINDVS_PATH} FINDVS)

function(VSRUN)
    cmake_parse_arguments(
        PARSED_ARGS # prefix of parameters
        "" # list of names of the boolean arguments (only defined ones will be true)
        "WD" # list of names of mono-valued arguments
        "CMD;NAME" # list of names of multi-valued arguments (output variables are lists)
        ${ARGN} # arguments of the function to parse, here we take the all original ones
    )
    message("${PARSED_ARGS_NAME}")
    file(APPEND ${LOG_FILE}
        "############# VSRUN ${PARSED_ARGS_NAME} ###########"
        "${PARSED_ARGS_CMD}"
        "#############################################"
    )
    
    set(TEMP_PATH "${CMAKE_CURRENT_LIST_DIR}/runvs-${PARSED_ARGS_NAME}_delete-me.ps1")
    file(WRITE ${TEMP_PATH}  "${FINDVS}\n\n" ${PARSED_ARGS_CMD})

    find_program(POWERSHELL
        NAMES powershell
        REQUIRED
    )
    
    set(BUILD_CMD "${POWERSHELL}" "${TEMP_PATH}")
    if(DEFINED LOG_FILE)
        set(VS_LOG_SETTING OUTPUT_FILE ${LOG_FILE} ERROR_FILE ${LOG_FILE} ${OUTPUT_QUIET})
    else()
        unset(VS_LOG_SETTING)
    endif()

    execute_process(
        COMMAND ${BUILD_CMD}
        WORKING_DIRECTORY ${PARSED_ARGS_WD}
        RESULT_VARIABLE RESULT
        COMMAND_ECHO STDOUT
        ${VS_LOG_SETTING}
    )

    if(RESULT)
        if(DEFINED LOG_FILE)
            file(READ ${LOG_FILE} LOG_STRING)
            message(FATAL_ERROR "${PARSED_ARGS_NAME} failed (${RESULT}).\nLOG:\n${LOG_STRING}")
        else()
            message(FATAL_ERROR "${PARSED_ARGS_NAME} failed (${RESULT})")
        endif()
    endif()

    if(NOT DEFINED VSRUN_NO_DEL)
        file(REMOVE ${TEMP_PATH})
    endif()
endfunction()







if(NOT MSVC AND SUDO_FETCH)
    set(SUDO "sudo ")
endif()

if(NOT DEFINED PARALLEL_FETCH)
    include(ProcessorCount)
    ProcessorCount(NUM_PROCESSORS)
    if(NOT NUM_PROCESSORS EQUAL 0)
        set(PARALLEL_FETCH ${NUM_PROCESSORS})
    else()
        set(PARALLEL_FETCH 1)
    endif()
endif()