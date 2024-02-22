add_library(diffie_hellman_lib diffie-hellman.c)
add_library(dhm_drbg_lib dhm_drbg.c)
target_include_directories(diffie_hellman_lib PUBLIC ${INCLUDE_DIR})
target_include_directories(dhm_drbg_lib PUBLIC ${INCLUDE_DIR})

target_link_libraries(diffie_hellman_lib PRIVATE mbedtls)
target_link_libraries(dhm_drbg_lib PRIVATE mbedtls)