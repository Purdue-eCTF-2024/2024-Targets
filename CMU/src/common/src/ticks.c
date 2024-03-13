/**
 * @file ticks.c
 * @author Plaid Parliament of Pwning
 * @brief Systick timer functions
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include "ticks.h"

#include <stdbool.h>
#include <stdint.h>

#include "max78000.h"

/**
 * @brief Enable SysTick 
 */
void tick_init() {
    // Polling with max range enabled (24-bit)
    SysTick->LOAD = 0x00ffffff;

    /*
     * SysTick_CTRL_CLKSOURCE_Msk : Use core's clock
     * SysTick_CTRL_ENABLE_Msk    : Enable SysTick
     * SysTick_CTRL_TICKINT_Msk   : Active the SysTick interrupt on the NVIC
     */
    SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;
}

/**
 * @brief Get the the systick value
 * 
 * @return uint32_t systick value
 */
uint32_t get_ticks() { return SysTick->VAL; }
