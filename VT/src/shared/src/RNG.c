/*
* RNG.c
* @brief This file contains the functions for the Random Number Generator, including initialization,
* generation of a nonce, and hashing the nonce and print the nonce and hash.
* @author CyberVT
* @note This file is part of the MITRE's 2024 Embedded System CTF (eCTF).
*/
/*********************************************************************************************************/
#include "RNG.h"

// Interrupt handler for TRNG
void TRNG_IRQHandler(void)
{
    MXC_TRNG_Handler();
}

// Function to print the message for debugging
void print16_m(char *stuff)
{
    printf("Message: \n");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", stuff[i]);
    }
    printf("\n\n");
}

void print32_m(char *stuff)
{
    printf("Message: \n");
    for (int i = 0; i < 32; ++i) {
        printf("%02x", stuff[i]);
    }
    printf("\n\n");
}

void print64_m(char *stuff)
{
    printf("Message: \n");
    for (int i = 0; i < 64; ++i) {
        printf("%02x", stuff[i]);
    }
    printf("\n\n");
}

void print96_m(char *stuff)
{
    printf("Message: \n");
    for (int i = 0; i < 96; ++i) {
        printf("%02x", stuff[i]);
    }
    printf("\n\n");
}

int RNG_init(uint8_t *rng_nonce, unsigned int num) {
    memset(rng_nonce, 0, num);
    MXC_TRNG_Init();
    MXC_TRNG_Random(rng_nonce, num_bytes);
    MXC_TRNG_Shutdown();
    return 1;
}

uint8_t * generate_nonce() {
    uint8_t nonce[16];
    //uint8_t message_hash[DIGEST_BYTES];       // Variable to store the hash
    uint8_t * message_hash = (uint8_t *)malloc(32 * sizeof(uint8_t));
    memset(nonce, 0, sizeof(nonce));
    MXC_TRNG_Init();
    MXC_TRNG_Random(nonce, num_bytes);
    MXC_TRNG_Shutdown();
    //print_success("Nonce generated...\n");
    //print16_m((char *)nonce);                           // Uncomment only while debugging
    size_t len = sizeof(nonce);
    sha256_ctx cx[1];
    sha256_begin(cx);
    sha256(message_hash, nonce, len, cx);
    //print_success("Hashing Done...\n");
    //print32_m((char *)message_hash);                         // Uncomment only while debugging
    return message_hash;
}
/*********************************************************************************************************/