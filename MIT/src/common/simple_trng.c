/**
 * @file "simple_trng.c"
 * @author MIT TechSec
 * @brief TRNG Interface
 * @date 2024
 */

#include "simple_trng.h"

/**
 * @brief Initialize TRNG hardware 
 */
void __attribute__((optimize("O0"))) simple_trng_init(void) {
    int ret = MXC_TRNG_Init();

    // REDUNDANT
    if ((ret != 0) || (ret != 0) || (ret != 0)) {
        while (1) { ; }
    }
}

/**
 * @brief Collect random bytes
 * 
 * @param buf: uint8_t*, ptr to random bytes store
 * @param num_bytes: int, number of random bytes to fetch
 */
void __attribute__((optimize("O0"))) get_rand_bytes(uint8_t * buf, int num_bytes) {
    int ret = 0;

    // REDUNDANT
    ret |= MXC_TRNG_Random(buf, num_bytes);
    ret |= MXC_TRNG_Random(buf, num_bytes);
    ret |= MXC_TRNG_Random(buf, num_bytes);

    // REDUNDANT
    if ((ret != 0) || (ret != 0) || (ret != 0)) {
        get_rand_bytes(buf, num_bytes);
    }
}