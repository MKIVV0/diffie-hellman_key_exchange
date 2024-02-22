add_executable(${PROJECT_NAME} ${SOURCE_DIR}/main.c)

target_link_libraries(${PROJECT_NAME} PUBLIC mbedtls dhm_drbg_lib diffie_hellman_lib)