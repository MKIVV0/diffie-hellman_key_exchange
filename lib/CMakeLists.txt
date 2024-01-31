add_library(number_gen_lib number_gen.c)
target_include_directories(number_gen_lib PUBLIC ${INCLUDE_DIR})

target_link_libraries(number_gen_lib PRIVATE mbedtls)