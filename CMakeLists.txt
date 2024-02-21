cmake_minimum_required(VERSION 3.18.4)
project(Diffie-Hellman_Key_Exchange VERSION 1.0.0 LANGUAGES C)

include(FetchContent)

FetchContent_Declare(
	mbedtls
	GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
	GIT_TAG v3.5.1
)

# Fetches and builds mbedtls from source code as a part of the build directory
# It may take a little while to download the library
FetchContent_MakeAvailable(mbedtls)

set(SOURCE_DIR ${CMAKE_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)

set(MBEDTLS_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/mbedtls/include)


add_subdirectory(lib)
add_subdirectory(src)
