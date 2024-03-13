/**
 * @file rng.c
 * @author Plaid Parliament of Pwning
 * @brief Random number generation functions
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include <stdint.h>
#include <stddef.h>
#include "rng.h"
#include "mxc_sys.h"
#include "max78000.h"
#include "monocypher.h"
#include "string.h"
#include "flc.h"
#include "rng.h"
#include "ticks.h"
#include "util.h"

#define RNG_STATE_ADDR 0x10042000
#define RNG_PREV_HASH (RNG_STATE_ADDR+64)
#define RNG_BUFFER_LEN 64
#define RNG_MAX_FAST_GENS 64

#define MXC_F_TRNG_REVB_STATUS_RDY_POS                 0 /**< STATUS_RDY Position */
#define MXC_F_TRNG_REVB_STATUS_RDY                     ((uint32_t)(0x1UL << MXC_F_TRNG_REVB_STATUS_RDY_POS)) /**< STATUS_RDY Mask */


#ifdef __cplusplus
#define __I volatile
#else
#define __I volatile const
#endif
#define __O volatile
#define __IO volatile 

typedef struct {
    __IO uint32_t ctrl;                 /**< <tt>\b 0x00:</tt> TRNG_REVB CTRL Register */
    __IO uint32_t status;               /**< <tt>\b 0x04:</tt> TRNG_REVB STATUS Register */
    __I  uint32_t data;                 /**< <tt>\b 0x08:</tt> TRNG_REVB DATA Register */
} mxc_trng_revb_regs_t;

typedef struct {
    __IO uint32_t ctrl;                 /**< <tt>\b 0x00:</tt> TRNG CTRL Register */
    __IO uint32_t status;               /**< <tt>\b 0x04:</tt> TRNG STATUS Register */
    __I  uint32_t data;                 /**< <tt>\b 0x08:</tt> TRNG DATA Register */
} mxc_trng_regs_t;


/**
 * @brief entropy pool
 */
uint8_t ram_entropy_pool[RNG_BUFFER_LEN];

/**
 * @brief rng fast generation counter - used to update the rng pool every 1 in x iterations
 */
uint32_t fast_gens = 0;

uint8_t *rng_key;

/**
 * @brief Get data from the hardware True RNG
 * 
 * @param trng trng pointer
 * @return random data 
 */
int rng_trng_int(mxc_trng_revb_regs_t *trng)
{
    while (!(trng->status & MXC_F_TRNG_REVB_STATUS_RDY)) {}

    return (int)trng->data;
}

/**
 * @brief Fills up a buffer with random data
 * 
 * @param data buffer pointer
 * @param len length of buffer
 */
void rng_get_trng_data(uint8_t *data, uint32_t len)
{
    unsigned int i, temp;

    if (data == NULL) {
        // HCF: The caller violated this function's contract
        // This can only happen due to a hardware fault
        HALT_AND_CATCH_FIRE();
    }

    for (i = 0; (i + 3) < len; i += 4) {
        temp = rng_trng_int((mxc_trng_revb_regs_t *)MXC_TRNG);
        memcpy(&(data[i]), (uint8_t *)(&temp), 4);
    }

    if (len & 0x03) {
        temp = rng_trng_int((mxc_trng_revb_regs_t *)MXC_TRNG);
        memcpy(&(data[i]), (uint8_t *)(&temp), len & 0x03);
    }
}

/**
 * @brief Get ticks and store into buffer
 * 
 * Data must store 64 bytes - 16 instances of the ticks value.
 * 
 * @param data buffer pointer
 */
void rng_get_ticks(uint8_t *data) {
    uint32_t ticks = get_ticks(); // 4 bytes
    for(int i = 0; i < 16; i++) {
        memcpy(data + i*4, &ticks, 4); // 16*4 = 64 bytes (RNG_BUFFER_LEN)
    }
}


/**
 * @brief Get Von Neuman whitened random data of RNG_BUFFER_LEN
 * 
 * @param data buffer pointer
 */
void rng_get_unbiased_trng(uint8_t *data) {
    uint8_t stream[RNG_BUFFER_LEN*4]; // Generate 4*64 bytes to reduce chance of later overhead

    uint8_t current_byte = 0;
    uint8_t bits_generated = 0;
    size_t buffer_idx = 0;

    while (buffer_idx < RNG_BUFFER_LEN) {
        rng_get_trng_data(stream, sizeof(stream)); 

        for (uint32_t i = 0; i < sizeof(stream); i++) {
            for (uint32_t bit = 0; bit < 8; bit+=2, stream[i] >>=2) {
                uint8_t bit1 = (stream[i] >> 1);
                uint8_t bit2 = stream[i];

                uint8_t diff = (bit1 ^ bit2) & 1;

                if (diff) {
                    current_byte <<= 1;
                    current_byte |= (bit1 & 1);
                    bits_generated++;

                    if (bits_generated == 8) {
                        data[buffer_idx] = current_byte;
                        
                        bits_generated = 0;
                        current_byte = 0;
                        buffer_idx += 1;

                        if (buffer_idx >= RNG_BUFFER_LEN) {
                            return;
                        }
                    }
                } 
            }
        }
    }
}

/**
 * @brief Initialize the rng module
 */
void rng_init() {
    // set RNG key pointer
    rng_key = (uint8_t*)RNG_STATE_ADDR;

    // Enable TRNG
    MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_TRNG);

    // Make sure flash is accessible
    while (MXC_FLC_Init() != E_NO_ERROR) {}
}
    
/**
 * @brief Generate 64 bytes of randomness from TRNG, ticks and seeded entropy from build time
 * 
 * @param output output buffer
 */
void rng_generate_64(uint8_t *output) { 

    uint32_t key_buffer_u32[RNG_BUFFER_LEN / sizeof(uint32_t)];
    uint8_t* key_buffer = (uint8_t*)key_buffer_u32;

    MXC_FLC_Read(RNG_STATE_ADDR, key_buffer, RNG_BUFFER_LEN);

    // TRNG
    uint8_t trng_data[RNG_BUFFER_LEN];
    rng_get_unbiased_trng(trng_data);

    uint8_t hashed_trng[RNG_BUFFER_LEN];
    crypto_blake2b_general(hashed_trng, RNG_BUFFER_LEN, key_buffer, RNG_BUFFER_LEN, trng_data, RNG_BUFFER_LEN);
    
    crypto_wipe(trng_data, RNG_BUFFER_LEN); 
    
    // Ticks
    uint8_t tick_data[RNG_BUFFER_LEN];
    rng_get_ticks(tick_data);
    
    uint8_t hashed_ticks[RNG_BUFFER_LEN];
    crypto_blake2b_general(hashed_ticks, RNG_BUFFER_LEN, key_buffer, RNG_BUFFER_LEN, tick_data, RNG_BUFFER_LEN);

    crypto_wipe(tick_data, RNG_BUFFER_LEN);

    // get previous hash
    uint32_t previous_u32[RNG_BUFFER_LEN / sizeof(uint32_t)];
    uint8_t* previous = (uint8_t*)previous_u32;

    MXC_FLC_Read(RNG_PREV_HASH, previous, RNG_BUFFER_LEN);

    uint32_t p_hash_u32[RNG_BUFFER_LEN / sizeof(uint32_t)];
    uint8_t* p_hash = (uint8_t*)p_hash_u32;

    for(uint32_t i = 0; i < RNG_BUFFER_LEN; i++) {
        p_hash[i] = hashed_trng[i] ^ hashed_ticks[i] ^ previous[i];
    }

    crypto_wipe(previous, RNG_BUFFER_LEN);
    crypto_wipe(hashed_ticks, RNG_BUFFER_LEN);
    crypto_wipe(hashed_trng, RNG_BUFFER_LEN);
    
    if (MXC_FLC_PageErase(RNG_STATE_ADDR) != E_NO_ERROR) {
        // HCF: We use hardcoded addresses, so the only way an erase operation can go wrong
        // is if the flash protections have somehow changed,
        // or the flash was somehow busy (which is impossible because we spin until the done flag is set).
        HALT_AND_CATCH_FIRE();
    }

    //save, write wants 32bit integer array, which is fine since we still tell it to write RNG_BUFFER_LEN bytes
    if (MXC_FLC_Write(RNG_STATE_ADDR, RNG_BUFFER_LEN, (uint32_t*)key_buffer) != E_NO_ERROR) {
        // HCF: We use hardcoded addresses, so the only way an erase operation can go wrong
        // is if the flash protections have somehow changed,
        // or the flash was somehow busy (which is impossible because we spin until the done flag is set).
        HALT_AND_CATCH_FIRE();
    }

    if (MXC_FLC_Write(RNG_PREV_HASH, RNG_BUFFER_LEN, (uint32_t*)p_hash) != E_NO_ERROR) {
        // HCF: We use hardcoded addresses, so the only way an erase operation can go wrong
        // is if the flash protections have somehow changed,
        // or the flash was somehow busy (which is impossible because we spin until the done flag is set).
        HALT_AND_CATCH_FIRE();
    }

    crypto_blake2b_general(output, RNG_BUFFER_LEN, key_buffer, RNG_BUFFER_LEN, (uint8_t*)p_hash, RNG_BUFFER_LEN);

    crypto_wipe(p_hash, RNG_BUFFER_LEN);
    crypto_wipe(key_buffer, RNG_BUFFER_LEN);
}

/**
 * @brief Generate random data for a buffer of any length
 * 
 * @param output output buffer
 * @param size length of buffer
 */
void rng_generate_bulk(uint8_t *output, uint32_t size) {
    uint32_t full_iterations = size / RNG_BUFFER_LEN;
     
    uint32_t i;
    for (i = 0; i < full_iterations; i++) {
        rng_generate_64(output + (i*RNG_BUFFER_LEN));
    }

    i *= RNG_BUFFER_LEN;
    if (i < size) {
        // we have extra bytes to generate
        uint8_t temp[RNG_BUFFER_LEN];
        rng_generate_64(temp);

        uint32_t left = size - i;
        for (uint32_t j = 0; j < left; ++j)
        {
            output[i + j] = temp[j];
        }
    }
}

/**
 * @brief Update the entropy pool
 */
void rng_pool_update() {
    uint8_t new_entropy[RNG_BUFFER_LEN];
    rng_generate_64(new_entropy);

    uint32_t key_buffer_u32[RNG_BUFFER_LEN / sizeof(uint32_t)];
    uint8_t* key_buffer = (uint8_t*)key_buffer_u32;

    MXC_FLC_Read(RNG_STATE_ADDR, key_buffer, RNG_BUFFER_LEN);

    uint8_t hash_input[RNG_BUFFER_LEN*2];

    memcpy(hash_input, ram_entropy_pool, RNG_BUFFER_LEN);
    memcpy(hash_input + RNG_BUFFER_LEN, new_entropy, RNG_BUFFER_LEN);

    crypto_wipe(new_entropy, RNG_BUFFER_LEN);

    crypto_blake2b_general(ram_entropy_pool, RNG_BUFFER_LEN, key_buffer, RNG_BUFFER_LEN, hash_input, sizeof(hash_input));

    crypto_wipe(key_buffer, RNG_BUFFER_LEN);

    fast_gens = 0;
}

/**
 * @brief Generates rng data faster using lesser crypto blake hashes
 * 
 * @param output output buffer
 */
void rng_generate_fast(uint8_t *output) {
    if (fast_gens++ >= RNG_MAX_FAST_GENS) {
        rng_pool_update();
    }

    uint32_t count_data[2];
    count_data[0] = get_ticks();
    count_data[1] = fast_gens;

    uint8_t raw_rng[8];

    rng_get_trng_data(raw_rng, 8);

    uint8_t hash_input_pool[RNG_BUFFER_LEN + sizeof(count_data)];
    uint8_t hash_input_result[RNG_BUFFER_LEN + sizeof(count_data) + sizeof(raw_rng)];

    // pool
    memcpy(hash_input_result, ram_entropy_pool, RNG_BUFFER_LEN);
    
    // pool || cur_ticks || counter
    memcpy(hash_input_result + RNG_BUFFER_LEN, count_data, sizeof(count_data));

    memcpy(hash_input_pool, hash_input_result, sizeof(hash_input_pool));

    // pool || cur_ticks || counter || raw_trng    
    memcpy(hash_input_result + RNG_BUFFER_LEN + sizeof(count_data), raw_rng, sizeof(raw_rng));

    crypto_wipe(count_data, sizeof(count_data));
    crypto_wipe(raw_rng, sizeof(raw_rng));

    uint32_t key_buffer_u32[RNG_BUFFER_LEN / sizeof(uint32_t)];
    uint8_t* key_buffer = (uint8_t*)key_buffer_u32;

    MXC_FLC_Read(RNG_STATE_ADDR, key_buffer, RNG_BUFFER_LEN);

    crypto_blake2b_general(ram_entropy_pool, RNG_BUFFER_LEN, key_buffer, RNG_BUFFER_LEN, hash_input_pool, sizeof(hash_input_pool));
    crypto_blake2b_general(output, RNG_BUFFER_LEN, key_buffer, RNG_BUFFER_LEN, hash_input_result, sizeof(hash_input_result));

    crypto_wipe(key_buffer, RNG_BUFFER_LEN);
    crypto_wipe(hash_input_pool, sizeof(hash_input_pool));
    crypto_wipe(hash_input_result, sizeof(hash_input_result));
}

/**
 * @brief Fills up buffer with random bytes 
 * 
 * Calls rng_generate_fast internally
 * 
 * @param output output buffer
 * @param size length of output buffer
 */
void rng_generate_bulk_fast(uint8_t *output, uint32_t size) {
    uint32_t full_iterations = size / RNG_BUFFER_LEN;
     
    uint32_t i;
    for (i = 0; i < full_iterations; i++) {
        rng_generate_fast(output + (i*RNG_BUFFER_LEN));
    }

    i *= RNG_BUFFER_LEN;
    if (i < size) {
        // we have extra bytes to generate
        uint8_t temp[RNG_BUFFER_LEN];
        rng_generate_fast(temp);

        for (int j = 0; (i + j) < size; j++) {
            output[i+j] = temp[j];
        } 
    }
}
