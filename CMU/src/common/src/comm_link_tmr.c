/**
 * @file comm_link_tmr.c
 * @author Plaid Parliament of Pwning
 * @brief Implements timer for link layer
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */

#include "comm_link_tmr.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "comm_link_def.h"
#include "tmr.h"
#include "util.h"  // For UTIL_ASSERT

/********** FORWARD DECLARATIONS ***********/

static void link_configure_timer(mxc_tmr_regs_t *timer, bool one_shot);

/********** FORWARD DECLARATIONS END ***********/

/**
 * @brief Shutsdown a timer
 * 
 * @param timer timer
 */
void link_stop_timer(mxc_tmr_regs_t *timer) {
    UTIL_ASSERT(timer);
    MXC_TMR_Shutdown(timer);
}

/**
 * @brief Starts a timer
 * 
 * @param timer timer
 * @param one_shot whether to overflow and start again or keep it one-shot
 */
void link_start_timer(mxc_tmr_regs_t *timer, bool one_shot) {
    UTIL_ASSERT(timer);
    link_stop_timer(timer);  // Stop the timer before configuration
    link_configure_timer(timer, one_shot);
    MXC_TMR_Start(timer);  // Start the timer immediately
}
    
/**
 * @brief Configures a timer
 * 
 * @param timer timer
 * @param one_shot whether to overflow and start again or keep it one-shot
 */
static void link_configure_timer(mxc_tmr_regs_t *timer, bool one_shot) {
    UTIL_ASSERT(timer);

    mxc_tmr_cfg_t cfg;
    cfg.pres = TMR_PRES_1;                // No prescaling (prescalar == 1)
    cfg.bitMode = TMR_BIT_MODE_32;        // 32-bit counter
    cfg.clock = MXC_TMR_APB_CLK;          // APB clock (30 MHz)
    cfg.cmp_cnt = LINK_TMR_PERIOD_TICKS;  // Ticks before overflow
    cfg.pol = 0;  // Polarity, doesn't matter for our use case

    if (one_shot) {
        cfg.mode = TMR_MODE_ONESHOT;  // One-shot mode, stops when overflows
    } else {
        cfg.mode = TMR_MODE_CONTINUOUS;  // Continuous mode, runs indefinitely
    }

    const bool init_pins = false;  // We don't need GPIO output
    const int init_ret = MXC_TMR_Init(timer, &cfg, init_pins);
    UTIL_ASSERT(init_ret == E_NO_ERROR);

    // Ensure that the counter is initialized to 1, so that the period is
    // LINK_TMR_PERIOD_TICKS
    timer->cnt = 1;
}

/**
 * @brief Convert timeout in milliseconds to number of link timer ticks
 * 
 * @param timeout_ms timeout in milliseconds
 * @return number of link timer ticks
 */
uint32_t link_timeout_ms_to_ticks(int32_t timeout_ms) {
    UTIL_ASSERT(timeout_ms <= LINK_MAX_TIMEOUT_MS);

    // The tick number used when the timeout is not specified (infinite),
    // MUST be >= LINK_TMR_PERIOD_TICKS so this value can never be reached
    // when the time difference is mod LINK_TMR_PERIOD_TICKS
    uint32_t timeout_ticks = 0xffffffffU;

    if (timeout_ms > 0) {  // Timeout specified
        timeout_ticks = (uint32_t)timeout_ms * LINK_NUM_TICKS_PER_MS;
        UTIL_ASSERT(timeout_ticks <= LINK_MAX_TIMEOUT_TICKS);
    }

    return timeout_ticks;
}
