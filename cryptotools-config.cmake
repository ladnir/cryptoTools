# find the location of where this file was installed. We expect includes/libs to be next to it
find_path(CRYPTO-TOOLS_INSTALL_DIR NAMES cmake/cryptotools-config.cmake)
find_library(CRYPTO-TOOLS_LIBRARY NAMES cryptoTools)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CRYPTO-TOOLS       DEFAULT_MSG CRYPTO-TOOLS_INSTALL_DIR CRYPTO-TOOLS_LIBRARY)

if(CRYPTO-TOOLS_FOUND)
	set(CRYPTO-TOOLS_LIBRARIES ${CRYPTO-TOOLS_LIBRARY})
	set(CRYPTO-TOOLS_INCLUDE_DIRS ${CRYPTO-TOOLS_INSTALL_DIR}/include/)
endif()
