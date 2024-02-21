#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#ifndef DHM_DRBG
#define DHM_DRBG

#define NUM_LEN_BIT                     256
#define NUM_LEN_BYTES         NUM_LEN_BIT*8
#define ENTROPY_SIZE                     64
#define RESEEDING_ROUND                1000

#define OPERATION_SUCCESS                 0

// Error macros
#define ERROR_ENTROPY_FAILURE            -1
#define ERROR_SEEDING_FAILURE            -2
#define ERROR_RESEEDING_FAILURE          -3
#define ERROR_NUMBER_GEN_FAILURE         -4

int init_drbg_contexts(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy);

int initial_seeding(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy, const unsigned char *personalization);

int generate_random_number(mbedtls_ctr_drbg_context *ctr_drbg, unsigned char *buffer, size_t buffer_len);

void free_drbg_contexts(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy);

#endif // DHM_DRBG