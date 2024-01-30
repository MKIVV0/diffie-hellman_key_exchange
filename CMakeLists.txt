cmake_minimum_required(VERSION 3.27.7)
project(Diffie-Hellman_Key_Exchange VERSION 1.0.0 LANGUAGES C)

include(FetchContent)

FetchContent_Declare(
	mbedtls
	GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
	GIT_TAG v3.5.1
)

# Fetches and builds mbedtls from source code as a subfolder
FetchContent_MakeAvailable(mbedtls)

add_subdirectory(include)
add_subdirectory(lib)
add_subdirectory(src)
