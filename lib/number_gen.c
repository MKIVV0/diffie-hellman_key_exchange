#include "number_gen.h"
#include <string.h>

int init_num_gen_contexts(mbedtls_ctr_drbg_context *drbg, mbedtls_entropy_context *entropy) {
    mbedtls_ctr_drbg_init(drbg);
    mbedtls_entropy_init(entropy);

    return OPERATION_SUCCESSFUL;
}

int free_num_gen_contexts(mbedtls_ctr_drbg_context *drbg, mbedtls_entropy_context *entropy) {
    mbedtls_ctr_drbg_free(drbg);
    mbedtls_entropy_free(entropy);

    return OPERATION_SUCCESSFUL;
}

int generate_random_number(mbedtls_ctr_drbg_context *drbg, mbedtls_entropy_context *entropy, const unsigned char *pers, mbedtls_mpi *num) {
    if (mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, entropy, pers, strlen(pers)) != 0) 
        return OPERATION_FAILED;
    
    if (mbedtls_mpi_gen_prime(num, NUM_BIT_LENGTH, MBEDTLS_MPI_GEN_PRIME_FLAG_DH, mbedtls_ctr_drbg_random, drbg) != 0)
        return OPERATION_FAILED;

    return OPERATION_SUCCESSFUL;
}

int init_mpi_vars(mbedtls_mpi *p, mbedtls_mpi *g) {
    mbedtls_mpi_init(p);
    mbedtls_mpi_init(g);

    return OPERATION_SUCCESSFUL;
}

int free_mpi_vars(mbedtls_mpi *p, mbedtls_mpi *g) {
    mbedtls_mpi_free(p);
    mbedtls_mpi_free(g);
    
    return OPERATION_SUCCESSFUL;
}

int mpi_to_str(mbedtls_mpi *num, uint8_t *buffer, size_t *olen) {
    if (mbedtls_mpi_write_string(num, 16, buffer, sizeof(buffer), olen) != 0)
        return OPERATION_FAILED;
    
    return OPERATION_SUCCESSFUL;
}