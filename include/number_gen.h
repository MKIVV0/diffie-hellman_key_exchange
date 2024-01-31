#ifndef NUMBER_GEN
#define NUMBER_GEN

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#define BUFFER_SIZE 128    // 128 * 8 = 1024 bits
#define SEED_SIZE 64        // 64 * 8 = 512 bits
#define OPERATION_SUCCESSFUL 0
#define OPERATION_FAILED 1

int init_num_gen_contexts(mbedtls_ctr_drbg_context *drbg, mbedtls_entropy_context *entropy);

int free_num_gen_contexts(mbedtls_ctr_drbg_context *drbg, mbedtls_entropy_context *entropy);

int generate_random_number(mbedtls_ctr_drbg_context *drbg, mbedtls_entropy_context *entropy, const unsigned char *pers, uint8_t *buffer);

#endif  // NUMBER_GEN