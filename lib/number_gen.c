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

int generate_random_number(mbedtls_ctr_drbg_context *drbg, mbedtls_entropy_context *entropy, const unsigned char *pers, uint8_t *buffer) {
    if (mbedtls_ctr_drbg_seed(drbg, mbedtls_entropy_func, entropy, pers, strlen(pers)) != 0) 
        return OPERATION_FAILED;
    
    
    if (mbedtls_ctr_drbg_random(drbg, buffer, BUFFER_SIZE) != 0)
        return OPERATION_FAILED;

    return OPERATION_SUCCESSFUL;
}