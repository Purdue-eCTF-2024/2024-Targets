/**
 * @file rng.h
 * @author Plaid Parliament of Pwning
 * @brief Function prototypes for random number generation
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include <stdint.h>

void rng_init();

void rng_generate_64(uint8_t *output);

// Fills up buffer with random bytes
void rng_generate_bulk(uint8_t *output, uint32_t size);

void rng_pool_update();

// Generates RNG_BUFFER_LEN random bytes
void rng_generate_fast(uint8_t *output);

void rng_generate_bulk_fast(uint8_t *output, uint32_t size);
