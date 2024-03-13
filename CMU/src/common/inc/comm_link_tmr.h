/**
 * @file comm_link_tmr.h
 * @author Plaid Parliament of Pwning
 * @brief Prototypes for link layer timer
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "comm_link_def.h"
#include "tmr.h"  // For mxc_tmr_regs_t

/**
 * @brief The period of the link layer timer
 */
#define LINK_TMR_PERIOD_TICKS ((uint32_t)0x80000000)  // MUST be 2^31

/**
 * @brief 30 MHz clock frequency (with a prescalar of 1)
 * 
 * NOTE: 30,000,000 < 4,294,967,295 == 2^32 - 1
 */
#define LINK_TMR_FREQUENCY_HZ ((uint32_t)30 * 1000 * 1000)

/**
 * @brief Number of ticks per ms
 */
#define LINK_NUM_TICKS_PER_MS (LINK_TMR_FREQUENCY_HZ / 1000)

/**
 * @brief The maximum allowed timeout
 */
#define LINK_MAX_TIMEOUT_TICKS (LINK_TMR_PERIOD_TICKS / 2)

void link_stop_timer(mxc_tmr_regs_t *timer);

void link_start_timer(mxc_tmr_regs_t *timer, bool one_shot);

uint32_t link_timeout_ms_to_ticks(int32_t timeout_ms);
