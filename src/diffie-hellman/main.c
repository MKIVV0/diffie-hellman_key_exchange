#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/dhm.h"

#include <stdio.h>
#include <time.h>
#include "diffie-hellman.h"


struct timespec start_time, end_time;
long elapsed_time;

int main(void) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    init_num_gen_contexts(&drbg, &entropy);
    
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
    
    return 0;
}