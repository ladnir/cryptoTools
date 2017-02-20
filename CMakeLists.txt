cmake_minimum_required (VERSION 2.8)



#############################################
#       Library/includes locations          #
#############################################

# default location for miracl
set(Miracl_Dirs "${CMAKE_SOURCE_DIR}/thirdparty/linux/miracl/")
include_directories("${Miracl_Dirs}") 
link_directories("${Miracl_Dirs}/miracl/source/")
install(FILES "${Miracl_Dirs}/miracl/source/libmiracl.a" DESTINATION lib)

# default location for Boost
set(BOOST_ROOT "${CMAKE_SOURCE_DIR}/thirdparty/linux/boost/")




#############################################
#       cryptoTools, tests, frontend        #
#############################################
include_directories(${CMAKE_CURRENT_SOURCE_DIR}) 


add_subdirectory(cryptoTools)
add_subdirectory(tests_cryptoTools)
add_subdirectory(frontend_cryptoTools)
