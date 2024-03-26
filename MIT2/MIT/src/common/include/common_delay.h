/**
 * @file "common_delay.h"
 * @brief Common delay defs
 */

#ifndef _COMMON_DELAY_H_
#define _COMMON_DELAY_H_

#include "simple_trng.h"

#define delay_1s MXC_Delay(1000000)
#define delay_4s MXC_Delay(4000000)
#define delay_rnd delay_random_small()

void delay_random_small(void);

#endif