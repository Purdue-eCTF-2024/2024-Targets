/**
 * @file "common_delay.c"
 * @author MIT TechSec
 * @brief Common delays
 * @date 2024
 */

#include "common_delay.h"

// 2.222*2 ms
#define small_delay_mod 4444

void delay_random_small(void) {
    uint32_t delay_us = 0;
    get_rand_bytes(&delay_us, sizeof(delay_us));

    MXC_Delay(delay_us % small_delay_mod);
}
