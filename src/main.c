#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"

#include <stdio.h>
#include <time.h>
#include "number_gen.h"

struct timespec start_time, end_time;
long elapsed_time;

int main(void) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_mpi p, g;
    size_t olen;
    uint8_t p_buff[NUM_BIT_LENGTH/8];
    uint8_t g_buff[NUM_BIT_LENGTH/8];

    init_mpi_vars(&p, &g);
    init_num_gen_contexts(&drbg, &entropy);
    
    printf("Starting the generation of p...\n");
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    generate_random_number(&drbg, &entropy, "diffie-hellman", &p);

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    elapsed_time = (end_time.tv_sec - start_time.tv_sec) * 1e9 +
                   (end_time.tv_nsec - start_time.tv_nsec);
    printf("The generation of p took %ld ns\n\n", elapsed_time);



    printf("Starting the generation of g...\n");
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    generate_random_number(&drbg, &entropy, "diffie-hellman", &g);

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    elapsed_time = (end_time.tv_sec - start_time.tv_sec) * 1e9 +
                   (end_time.tv_nsec - start_time.tv_nsec);
    printf("The generation of g took %ld ns\n", elapsed_time);



    mpi_to_str(&p, p_buff, &olen);
    mpi_to_str(&g, g_buff, &olen);

    printf("Public parameters of %u bits:\np: ", NUM_BIT_LENGTH);
    for (int i = 0; i < sizeof(p_buff); i++)
        printf("%u", p_buff[i]);
    printf("\ng: ");
    for (int i = 0; i < sizeof(g_buff); i++)
        printf("%u", g_buff[i]);
    printf("\n");
    
    free_num_gen_contexts(&drbg, &entropy);
    free_mpi_vars(&p, &g);
    
    return 0;
}