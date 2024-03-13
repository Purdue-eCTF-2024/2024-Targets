/**
 * @file fiproc.c
 * @author Plaid Parliament of Pwning
 * @brief Fault injection protections functions
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include <stdint.h>
#include "fiproc.h"
#include "ticks.h"
#include "rng.h"
#include "util.h"
#include "max78000.h"
#include "crypto_wrappers.h"
#include "mxc_delay.h"
#include <stddef.h>

#define FIPROC_POOL_SIZE_PAGES 32
#define FIPROC_POOL_SIZE (CC_HASH_LEN * FIPROC_POOL_SIZE_PAGES)

/**
 * Macro used to specify a microsecond timing parameter in seconds.
 * x = SEC(3) // 3 seconds -> x = 3,000,000
 */
#define MXC_DELAY_SEC(s) (((uint32_t)s) * 1000000UL)
/**
 * Macro used to specify a microsecond timing parameter in milliseconds.
 * x = MSEC(3) // 3ms -> x = 3,000
 */
#define MXC_DELAY_MSEC(ms) (ms * 1000UL)
/**
 * Macro used to specify a microsecond timing parameter.
 * x = USEC(3) // 3us -> x = 3
 */
#define MXC_DELAY_USEC(us) (us)

uint8_t pool_tmp[CC_HASH_LEN] = {0};
uint8_t pool[FIPROC_POOL_SIZE] = {0};
uint8_t *next = NULL;

/**
 * @brief Update the entropy pool used by fiproc code
 */
void fiproc_load_pool()
{
    rng_generate_bulk(pool_tmp, CC_HASH_LEN);

    // Expand the pool by hashing it with indices
    for (uint32_t i = 0; i < FIPROC_POOL_SIZE_PAGES; i++) {
        cc_hash_internal(pool+(i*CC_HASH_LEN), CC_HASH_LEN, (uint8_t*)&i, sizeof(i), pool_tmp, CC_HASH_LEN, 1);
        xor_bytes(pool+(i*CC_HASH_LEN), pool_tmp, CC_HASH_LEN);
    }
    next = &pool[0];
}


/**
 * @brief Random sleep <1ms to deter side channels
 * 
 * Max delay of 2^16 ticks
 */
int fiproc_delay()
{
    if(next == NULL) {
        fiproc_load_pool();
    }

    if ((uintptr_t)next - (uintptr_t)&pool >= (FIPROC_POOL_SIZE - 1)) {
        fiproc_load_pool();
    }

    uint32_t delay = (((uint32_t)(*next)) << 8) | ((uint32_t)(*(next + 1)));
    next += 2;

    delay = delay & 0x3FF; // 10 bits of granularity ~= 426us

    volatile uint32_t i = 0;
    for (; i < delay; ++i);

    return 0;
}

/**
 * @brief Random sleep of 50-120ms to deter attacks
 */
int fiproc_ranged_delay()
{
    if(next == NULL) {
        fiproc_load_pool();
    }
    
    if ((uintptr_t)next - (uintptr_t)&pool >= (FIPROC_POOL_SIZE - 1)) {
        fiproc_load_pool();
    }

    uint32_t delay = (((uint32_t)(*next)) << 8) | ((uint32_t)(*(next + 1)));
    next += 2;

    delay = delay >> 2;

    uint32_t ranged_delay_us = delay + (uint32_t)MXC_DELAY_MSEC(20); // 20-36ms

    MXC_Delay(ranged_delay_us);
    fiproc_delay();

    return 0;
}
