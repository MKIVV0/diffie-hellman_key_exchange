#include "mbedtls/dhm.h"
#include "mbedtls/ctr_drbg.h"

#ifndef DIFFIE_HELLMAN
#define DIFFIE_HELLMAN

// PARAMETER SIZES
#define SK_LENGTH_BITS                            64
#define SK_LENGTH_BYTES             SK_LENGTH_BITS*8 
#define PK_LENGTH_BITS                           256
#define PK_LENGTH_BYTES             PK_LENGTH_BITS*8 
#define SHARED_SECRET_BITS                        32   // FOR NOW, A RANDOM VALUE
#define SHARED_SECRET_BYTES     SHARED_SECRET_BITS*8

// DETERMINISTIC VALUES 
#define PRIME_MODULUS \
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
#define GENERATOR "2"

// SUCCESS CODE
#define DH_OPERATION_SUCCESS                       0

// ERROR CODES
#define ERROR_MPI_PRIME_GEN_FAILURE               -1
#define ERROR_ZP_GROUP_CREATION_FAILURE           -2
#define ERROR_KEY_PAIR_GEN_FAILURE                -3
#define ERROR_PEER_KEY_IMPORT_FAILURE             -4
#define ERROR_SHARED_SECRET_GEN_FAILURE           -5

// Initialize the mbedtls_dhm_context structure, set P and G, and set Z_p.
int init_dh_context(mbedtls_dhm_context *dhm);

// generate the Diffie-Hellman key pair and return the public key.
int generate_key_pair(mbedtls_dhm_context *dhm, mbedtls_ctr_drbg_context *ctr_drbg, unsigned char* pk, size_t pk_len);

// Compute the shared secret using the peer's public key.
int compute_shared_secret(mbedtls_dhm_context *dhm, mbedtls_ctr_drbg_context *ctr_drbg, const unsigned char *peer_pk, size_t peer_pk_len, unsigned char *shared_secret, size_t shared_secret_len);

#endif // DIFFIE_HELLMAN