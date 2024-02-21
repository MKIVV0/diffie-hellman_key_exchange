add_library(diffie_hellman_lib number_gen.c)
target_include_directories(diffie_hellman_lib PUBLIC ${INCLUDE_DIR})

target_link_libraries(diffie_hellman_lib PRIVATE mbedtls)