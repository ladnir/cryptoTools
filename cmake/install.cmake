





#############################################
#            Install                        #
#############################################


configure_file("${CMAKE_CURRENT_LIST_DIR}/cryptoToolsDepHelper.cmake" "cryptoToolsDepHelper.cmake" COPYONLY)

# make cache variables for install destinations
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)


# generate the config file that is includes the exports
configure_package_config_file(
  "${CMAKE_CURRENT_LIST_DIR}/Config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/cryptoToolsConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cryptoTools
  NO_SET_AND_CHECK_MACRO
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

if(NOT DEFINED cryptoTools_VERSION_MAJOR)
    message("\n\n\n\n warning, cryptoTools_VERSION_MAJOR not defined ${cryptoTools_VERSION_MAJOR}")
endif()

set_property(TARGET cryptoTools PROPERTY VERSION ${cryptoTools_VERSION})

# generate the version file for the config file
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/cryptoToolsConfigVersion.cmake"
  VERSION "${cryptoTools_VERSION_MAJOR}.${cryptoTools_VERSION_MINOR}.${cryptoTools_VERSION_PATCH}"
  COMPATIBILITY AnyNewerVersion
)

# install the configuration file
install(FILES
          "${CMAKE_CURRENT_BINARY_DIR}/cryptoToolsConfig.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/cryptoToolsConfigVersion.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/cryptoToolsDepHelper.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cryptoTools
)

# install library
install(
    TARGETS cryptoTools tests_cryptoTools
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    EXPORT cryptoToolsTargets)

# install headers
install(
    DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/../cryptoTools"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/"
    FILES_MATCHING PATTERN "*.h")
#install config header
install(
    DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/cryptoTools"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/"
    FILES_MATCHING PATTERN "*.h")

# tests_cryptoTools headers
install(
    DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/../tests_cryptoTools"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/"
    FILES_MATCHING PATTERN "*.h")

# install config
install(EXPORT cryptoToolsTargets
  FILE cryptoToolsTargets.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cryptoTools
       NAMESPACE oc::
)
 export(EXPORT cryptoToolsTargets
       FILE "${CMAKE_CURRENT_BINARY_DIR}/cryptoToolsTargets.cmake"
       NAMESPACE oc::
)