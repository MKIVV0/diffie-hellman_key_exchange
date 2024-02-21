#include "diffie-hellman.h"
#include "mbedtls/ctr_drbg.h"

void init_dh_params(mbedtls_dhm_context *dhm) {
    mbedtls_dhm_init(&dhm);
}

int generate_key_pair(mbedtls_dhm_context *dhm, mbedtls_ctr_drbg_context *ctr_drbg, unsigned char* pk, size_t pk_len) {
    int ret;

    ret = mbedtls_dhm_make_params(&dhm, mbedtls_mpi_size(&dhm->private_P), pk, pk_len, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (ret != 0)
        return ERROR_KEY_PAIR_GEN_FAILURE;
}


int compute_shared_secret(mbedtls_dhm_context *dhm, mbedtls_ctr_drbg_context *ctr_drbg, const unsigned char *peer_pk, size_t peer_pk_len, unsigned char *shared_secret, size_t shared_secret_len) {
    int ret;
    
    // import the peer's public key
    ret = mbedtls_dhm_read_public(&dhm, peer_pk, peer_pk_len);

    if (ret != 0)
        return ERROR_PEER_KEY_IMPORT_FAILURE;

    ret = mbedtls_dhm_calc_secret(&dhm, shared_secret, shared_secret_len, &shared_secret_len, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (ret != 0)
        return ERROR_SHARED_SECRET_GEN_FAILURE;
}

void free_dh_params(mbedtls_dhm_context *dhm) {
    mbedtls_dhm_free(&dhm);
}