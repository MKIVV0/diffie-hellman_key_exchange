#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <stdio.h>
#include "number_gen.h"

int main(void) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;

    init_num_gen_contexts(&drbg, &entropy);
    uint8_t buffer[BUFFER_SIZE];
    
    generate_random_number(&drbg, &entropy, "diffie-hellman", buffer);
    free_num_gen_contexts(&drbg, &entropy);

    printf("Random number: ");
    for (int i = 0; i < BUFFER_SIZE; i++)
        printf("%x", buffer[i]);
    printf("\n");
    
    return 0;
}