#ifndef NUMBER_GEN
#define NUMBER_GEN

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/bignum.h"

#define NUM_BIT_LENGTH 256*8    // 256 * 8 = 2048 bits
#define SEED_SIZE 64        // 64 * 8 = 512 bits
#define OPERATION_SUCCESSFUL 0
#define OPERATION_FAILED 1

int init_num_gen_contexts(mbedtls_ctr_drbg_context *drbg, mbedtls_entropy_context *entropy);

int free_num_gen_contexts(mbedtls_ctr_drbg_context *drbg, mbedtls_entropy_context *entropy);

int generate_random_number(mbedtls_ctr_drbg_context *drbg, mbedtls_entropy_context *entropy, const unsigned char *pers, mbedtls_mpi *num);

int init_mpi_vars(mbedtls_mpi *p, mbedtls_mpi *q);

int free_mpi_vars(mbedtls_mpi *p, mbedtls_mpi *q);

int mpi_to_str(mbedtls_mpi *num, uint8_t *buffer, size_t *olen);

#endif  // NUMBER_GEN