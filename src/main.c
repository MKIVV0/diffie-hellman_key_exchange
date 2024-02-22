#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/dhm.h"

#include <stdio.h>
#include <time.h>
#include "diffie-hellman.h"
#include "dhm_drbg.h"


struct timespec start_time, end_time;
long elapsed_time;

int main(void) {
    /* Placeholder for return codes */
    int ret;

    /* Placeholders for the two private keys, i.e. a and b */
    unsigned char alice_secret_key[SK_LENGTH_BYTES];
    unsigned char bob_secret_key[SK_LENGTH_BYTES];

    /* Placeholders for the two public keys, i.e. g^a mod p and g^b mod p */
    unsigned char alice_public_key[PK_LENGTH_BYTES];
    unsigned char bob_public_key[PK_LENGTH_BYTES];

    /* Placeholders for the two shared secrets */
    unsigned char alice_shared_secret[PK_LENGTH_BYTES];
    unsigned char bob_shared_secret[PK_LENGTH_BYTES];

    /* Entropy and DRBG contexts for generating the random prime numbers */
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    printf("1\n");
    init_drbg_contexts(&ctr_drbg, &entropy);
    printf("2\n");

    /* Alice and Bob */
    mbedtls_dhm_context alice;
    printf("2.1\n");
    mbedtls_dhm_context bob;
    printf("2.2\n");

    printf("STARTING THE DIFFIE-HELLMAN SIMULATION...\n");
    
    // 1. Alice and Bob publicly agree on a shared key to use (p, g)
    /* Initialize both Alice's and Bob's contexts */
    printf("3\n");
    init_dh_context(&alice);
    printf("4\n");
    init_dh_context(&bob);
    printf("5\n");

    // 2. Alice generates a secret key, combines it with the shared key and sends it (public value) to Bob
    printf("6\n");
    generate_key_pair(&alice, &ctr_drbg, alice_public_key, sizeof(alice_public_key));

    printf("7\n");
    // 3. Bob generates a secret key, combines it with the shared key and sends it (public value) to Alice
    generate_key_pair(&bob, &ctr_drbg, bob_public_key, sizeof(bob_public_key));

    printf("8\n");
    // 4. Alice combines Bob's public value with her secret key
    compute_shared_secret(&alice, &ctr_drbg, bob_public_key, sizeof(bob_public_key), alice_shared_secret, sizeof(alice_shared_secret));

    printf("9\n");
    // 5. Bob combines Alice's public value with his secret key
    compute_shared_secret(&bob, &ctr_drbg, alice_public_key, sizeof(alice_public_key), bob_shared_secret, sizeof(bob_shared_secret));

    printf("10\n");
    // Test for the equality of the two shared secrets
    int passed = 1;
    for (size_t i = 0; i < sizeof(alice_shared_secret); i++) {
        if (alice_shared_secret[i] != bob_shared_secret[i]) {
            passed = 0;
            break;
        }
    }
    if (passed == 1) printf("The two shared secrets are the same!\n");
    else printf("The two shared secrets are not the same!\n");

    printf("11\n");
    // The shared secret
    printf("Shared secret: 0x");
    for (size_t i = 0; i < sizeof(alice_shared_secret); i++) 
        printf("%x", alice_shared_secret[i]);
    printf("\n");

    printf("12\n");
    /* Free all the contexts */
    mbedtls_dhm_free(&alice);
    mbedtls_dhm_free(&bob);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    printf("ENDING THE DIFFIE-HELLMAN SIMULATION...\n");


    /*
    printf("Starting the generation of p...\n");
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // code...

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    elapsed_time = (end_time.tv_sec - start_time.tv_sec) * 1e9 +
                   (end_time.tv_nsec - start_time.tv_nsec);
    printf("The generation of p took %ld ns\n\n", elapsed_time);



    printf("Starting the generation of g...\n");
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    // code...

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    elapsed_time = (end_time.tv_sec - start_time.tv_sec) * 1e9 +
                   (end_time.tv_nsec - start_time.tv_nsec);
    printf("The generation of g took %ld ns\n", elapsed_time);
    
    free_num_gen_contexts(&drbg, &entropy);
    */
    
    return 0;
}