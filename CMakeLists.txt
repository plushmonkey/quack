cmake_minimum_required(VERSION 3.2)

# Enable CMAKE_MSVC_RUNTIME_LIBRARY
cmake_policy(SET CMP0091 NEW)

project(quack VERSION 0.0.1 LANGUAGES CXX)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_CXX_STANDARD 20)

if(WIN32)
add_definitions(-D_CRT_SECURE_NO_WARNINGS -DNDEBUG -DNOMINMAX -DWIN32_LEAN_AND_MEAN)
elseif(UNIX)
endif()

include(GNUInstallDirs)

file(GLOB_RECURSE SOURCES quack/*.cpp)

add_executable(quack ${SOURCES})

if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  # Use parallel compilation
  target_compile_options(quack PRIVATE "/MP")
endif()

target_include_directories(quack PRIVATE
                           .)

if(WIN32)
  target_link_libraries(quack ws2_32)
else()
  target_link_libraries(quack dl -pthread -static)
endif()

set(CPACK_PACKAGE_NAME "quack")
set(CPACK_PACKAGE_VENDOR "plushmonkey")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "quack - quack")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "quack")

set(CMAKE_INSTALL_PREFIX ".")

install(TARGETS quack 
        CONFIGURATIONS Debug
        RUNTIME DESTINATION Debug)
        
install(TARGETS quack 
        CONFIGURATIONS Release
        RUNTIME DESTINATION Release)
