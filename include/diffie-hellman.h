#include "mbedtls/dhm.h"

#ifndef DIFFIE_HELLMAN
#define DIFFIE_HELLMAN

// PARAMETER SIZES
#define PK_LENGTH_BITS                          1024
#define PK_LENGTH_BYTES             PK_LENGTH_BITS*8 
#define SHARED_SECRET_BITS                        32   // FOR NOW, A RANDOM VALUE
#define SHARED_SECRET_BYTES     SHARED_SECRET_BITS*8

#define DH_OPERATION_SUCCESS                       0

// ERROR CODES
#define ERROR_KEY_PAIR_GEN_FAILURE                -1
#define ERROR_PEER_KEY_IMPORT_FAILURE             -2
#define ERROR_SHARED_SECRET_GEN_FAILURE           -3

// Initialize the mbedtls_dhm_context structure.
void init_dh_params(mbedtls_dhm_context *dhm);

// generate the Diffie-Hellman key pair and return the public key.
int generate_key_pair(mbedtls_dhm_context *dhm, mbedtls_ctr_drbg_context *ctr_drbg, unsigned char* pk, size_t pk_len);

// Compute the shared secret using the peer's public key.
int compute_shared_secret(mbedtls_dhm_context *dhm, const unsigned char *peer_pk, size_t peer_pk_len, 
                            unsigned char *shared_secret, size_t shared_secret_len);

void free_dh_params(mbedtls_dhm_context *dhm);

#endif DIFFIE_HELLMAN