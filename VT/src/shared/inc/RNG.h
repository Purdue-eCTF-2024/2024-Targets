/*
* @brief Header file for the Random Number Generator; RNG.c
* @file RNG.h
* @note This file contains the functions for the Random Number Generator, including initialization, 
* generation of a nonce, and hashing the nonce and print the nonce and hash.
* @author: CyberVT
* @note This file is part of the MITRE's 2024 Embedded System CTF (eCTF).
*/
/*********************************************************************************************************/
#include "sha2.h"
#include "stdio.h"
#include "string.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"
#include "trng.h"
#include <stdbool.h>
#include <stdint.h>

#define num_bytes 16                            // Number of bytes for the nonce
/*********************************************************************************************************/
/*
* @brief Initialize the Random Number Generator for Siginng and Verifying
* @return void
*/
int RNG_init(uint8_t *rng_nonce, unsigned int num);
/*
* @brief Generate a nonce and hash it
* @return uint8_t *, pointer to the hash of the nonce
*/
uint8_t * generate_nonce(void);
/*
* @brief Printing of the messages for debugging
* @param stuff: char *, printing of messages of size 16
* @return void
*/
void print16_m(char *stuff);
/*
* @brief Printing of the messages for debugging
* @param stuff: char *, printing of messages of size 32
* @return void
*/
void print32_m(char *stuff);
/*
* @brief Printing of the messages for debugging
* @param stuff: char *, printing of messages of size 64
* @return void
*/
void print64_m(char *stuff);
/*
* @brief Printing of the messages for debugging
* @param stuff: char *, printing of messages of size 96
* @return void
*/
void print96_m(char *stuff);
/*********************************************************************************************************/