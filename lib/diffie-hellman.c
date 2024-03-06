#include "diffie-hellman.h"
#include "mbedtls/ctr_drbg.h"

int init_dh_context(mbedtls_dhm_context *dhm) {
    int ret;

    mbedtls_dhm_init(dhm);

    /* The public shared key (P, G) */
    mbedtls_mpi P;     // modulus
    mbedtls_mpi G;     // generator

    /* Initialize P and G */
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&G);
    
    /* Set a deterministic value for P, by parsing the string value as hex */
    ret = mbedtls_mpi_read_string(&P, 16, PRIME_MODULUS);
    if (ret != 0) {
        fprintf(stderr, "Error code: 0x%x\n", ret);
        mbedtls_mpi_free(&P);  // Free P and G before returning
        mbedtls_mpi_free(&G);
        return ERROR_MPI_PRIME_GEN_FAILURE;
    }

    /* Set a deterministic value for G, by parsing the string value as hex */
    ret = mbedtls_mpi_read_string(&G, 16, GENERATOR);
    if (ret != 0) {
        fprintf(stderr, "Error code: 0x%x\n", ret);
        mbedtls_mpi_free(&P);  // Free P and G before returning
        mbedtls_mpi_free(&G);
        return ERROR_MPI_PRIME_GEN_FAILURE;
    }

    /* Set the Z_p group */
    ret = mbedtls_dhm_set_group(dhm, &P, &G);
    if (ret != 0) {
        fprintf(stderr, "Error code: 0x%x\n", ret);
        mbedtls_mpi_free(&P);  // Free P and G before returning
        mbedtls_mpi_free(&G);
        return ERROR_ZP_GROUP_CREATION_FAILURE;
    }

    /* Free P and G */
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&G);

    return DH_OPERATION_SUCCESS;
}



/* Generate the public key, i.e. either g^a mod p or g^b mod p */
int generate_key_pair(mbedtls_dhm_context *dhm, mbedtls_ctr_drbg_context *ctr_drbg, unsigned char* pk, size_t pk_len) {
    int ret;

    ret = mbedtls_dhm_make_params(dhm, mbedtls_mpi_size(&dhm->private_P), pk, &pk_len, mbedtls_ctr_drbg_random, ctr_drbg);

    if (ret != 0) {
        fprintf(stderr, "Error code: 0x%x\n", ret);
        return ERROR_KEY_PAIR_GEN_FAILURE;
    }
    
    return DH_OPERATION_SUCCESS;
}

/* Compute the shared secret, i.e. g^(ab) mod p */
int compute_shared_secret(mbedtls_dhm_context *dhm, mbedtls_ctr_drbg_context *ctr_drbg, const unsigned char *peer_pk, size_t peer_pk_len, unsigned char *shared_secret, size_t shared_secret_len) {
    int ret;
    
    printf("PK: 0x");
    for (int i = 0; i < peer_pk_len; i++)
        printf("%x", peer_pk[i]);
    printf("\n");

    // import the peer's public key
    ret = mbedtls_dhm_read_public(dhm, peer_pk, peer_pk_len);
    printf("1\n");
    if (ret != 0) {
        fprintf(stderr, "Error code: 0x%x\n", ret);
        return ERROR_PEER_KEY_IMPORT_FAILURE;
    }
    printf("2\n");
    ret = mbedtls_dhm_calc_secret(dhm, shared_secret, shared_secret_len, &shared_secret_len, mbedtls_ctr_drbg_random, ctr_drbg);
    printf("3\n");
    if (ret != 0) {
        fprintf(stderr, "Error code: 0x%x\n", ret);
        return ERROR_SHARED_SECRET_GEN_FAILURE;
    }

    return DH_OPERATION_SUCCESS;
}