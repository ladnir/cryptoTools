include("${CMAKE_CURRENT_LIST_DIR}/cryptoToolsFindBuildDir.cmake")


if(NOT EXISTS "${cryptoTools_BIN_DIR}")
	message(FATAL_ERROR "failed to find cryptoTools build directoy")
endif()


find_library(
    cryptoTools_LIB
    NAMES cryptoTools
    HINTS "${cryptoTools_BIN_DIR}/cryptoTools")
if(NOT cryptoTools_LIB)
    message(FATAL_ERROR "failed to find cryptoTools at ${libOTe_BIN_DIR}/cryptoTools/cryptoTools")
endif()


set(cryptoTools_INC "${cryptoTools_BIN_DIR};${CMAKE_CURRENT_LIST_DIR}/..;")

include("${CMAKE_CURRENT_LIST_DIR}/cryptoToolsDepHelper.cmake")