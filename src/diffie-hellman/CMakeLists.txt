add_executable(${PROJECT_NAME} ${SOURCE_DIR}/main.c)

target_link_libraries(${PROJECT_NAME} PUBLIC mbedtls number_gen_lib)