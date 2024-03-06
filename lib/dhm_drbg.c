#include "dhm_drbg.h"
#include <stdio.h>
#include <string.h>

int init_drbg_contexts(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy) {
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_entropy_init(entropy);
    
    const char *pers = "diffie-hellman";
    int ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy, pers, strlen(pers));
    if (ret != 0) {
        fprintf(stderr, "Something went wrong with the initial seeding! Error: 0x%x\n", ret);
        return ERROR_ENTROPY_FAILURE;
    }

    mbedtls_ctr_drbg_set_prediction_resistance(ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON );

    return OPERATION_SUCCESS;
}

/*
int initial_seeding(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy, const unsigned char *personalization) {
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, personalization, sizeof(personalization));

    if (ret != 0)
        fprintf(stderr, "Something went wrong with the initial seeding! Error: 0x%x\n", ret);
        return ERROR_SEEDING_FAILURE;

    return OPERATION_SUCCESS;
}
*/

int generate_random_number(mbedtls_ctr_drbg_context *ctr_drbg, unsigned char *buffer, size_t buffer_len) {
    static int rounds_since_reseeding = 0;
    int ret = 0;

    if (rounds_since_reseeding >= RESEEDING_ROUND) {
        ret = mbedtls_ctr_drbg_reseed(ctr_drbg, NULL, 0);

        if (ret != 0) return ERROR_RESEEDING_FAILURE;

        rounds_since_reseeding = 0;
    }

    ret = mbedtls_ctr_drbg_random(ctr_drbg, buffer, buffer_len);

    if (ret != 0)
        fprintf(stderr, "The random number generation went wrong! Error: 0x%x\n", ret);
        return ERROR_NUMBER_GEN_FAILURE;

    rounds_since_reseeding++;
    
    return OPERATION_SUCCESS;
}

void free_drbg_contexts(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy) {
    mbedtls_ctr_drbg_free(ctr_drbg);
    mbedtls_entropy_free(entropy);
}