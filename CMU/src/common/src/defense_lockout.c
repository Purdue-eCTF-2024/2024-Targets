/**
 * @file defense_lockout.c
 * @author Plaid Parliament of Pwning
 * @brief A defensive lockout with a reset prevention canary
 * 
 * When some functionality goes wrong, a timeout can be enforced which is done by the 
 * functions defined below. If a reset occurs, then the canary ensures that a timeout 
 * is reenforced.
 * 
 * If flash read/erase/write fails then a hardware attack has happened. 
 * In that case halt and catch fire.
 * 
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include "defense_lockout.h"
#include "mxc_delay.h"
#include "flc.h"
#include "util.h"

/**
 * @brief Address of lockout storage
 */
#define LOCKOUT_STATE_ADDR 0x10040000

/**
 * @brief Number of lockout time periods
 */
#define LOCKOUT_TIME_PD 35

/**
 * @brief Lockout period duration
 */
#define LOCKOUT_PD_US 100000 

/**
 * @brief Lockout function that checks flash state and locks out for given number of time periods
 * 
 * @return true if the lockout canary was 0, else false
 */
bool _defense_lockout_proc() {
    uint32_t tmp = 0;
    MXC_FLC_Read(LOCKOUT_STATE_ADDR, &tmp, sizeof(tmp));

    if (tmp > LOCKOUT_TIME_PD) {
        tmp = LOCKOUT_TIME_PD;
        // ASSERT: failure to write flash = hardware failure
        UTIL_ASSERT(MXC_FLC_PageErase(LOCKOUT_STATE_ADDR) == SUCCESS_RETURN);
        UTIL_ASSERT(MXC_FLC_Write(LOCKOUT_STATE_ADDR, sizeof(tmp), &tmp) == SUCCESS_RETURN);
    }

    MXC_FLC_Read(LOCKOUT_STATE_ADDR, &tmp, sizeof(tmp));

    volatile bool was_zero = (tmp == 0);

    while (tmp > 0) {
        MXC_Delay(LOCKOUT_PD_US);
        tmp--;

        // ASSERT: failure to write flash = hardware failure
        UTIL_ASSERT(MXC_FLC_PageErase(LOCKOUT_STATE_ADDR) == SUCCESS_RETURN);
        UTIL_ASSERT(MXC_FLC_Write(LOCKOUT_STATE_ADDR, sizeof(tmp), &tmp) == SUCCESS_RETURN);
    }

    tmp = 0;
    // ASSERT: failure to write flash = hardware failure
    UTIL_ASSERT(MXC_FLC_PageErase(LOCKOUT_STATE_ADDR) == SUCCESS_RETURN);
    UTIL_ASSERT(MXC_FLC_Write(LOCKOUT_STATE_ADDR, sizeof(tmp), &tmp) == SUCCESS_RETURN);

    return was_zero;
}

/**
 * @brief Call in main() to check if there was a reset during a previous wrong attempt 
 * and if so then enforce lockout
 */
void defense_lockout_init() {
   if (_defense_lockout_proc()) {
        MXC_Delay(20000);
   }
}

/**
 * @brief Call before some lockout-able functionality 
 */
void defense_lockout_start() {
    // Erase the lockout state page
    UTIL_ASSERT(MXC_FLC_PageErase(LOCKOUT_STATE_ADDR) == SUCCESS_RETURN);
}

/**
 * @brief Call after a lockout-able operation
 * 
 * @param delay true -> extra 5sec delay (attack detected), false -> return immediately
 */
void defense_lockout_clear(bool delay) {
    if (delay) {
        uint32_t tmp = LOCKOUT_TIME_PD;
        // ASSERT: failure to write flash = hardware failure
        UTIL_ASSERT(MXC_FLC_PageErase(LOCKOUT_STATE_ADDR) == SUCCESS_RETURN);
        UTIL_ASSERT(MXC_FLC_Write(LOCKOUT_STATE_ADDR, sizeof(tmp), &tmp) == SUCCESS_RETURN);
    } else {
        uint32_t tmp = 0;
        // ASSERT: failure to write flash = hardware failure
        UTIL_ASSERT(MXC_FLC_PageErase(LOCKOUT_STATE_ADDR) == SUCCESS_RETURN);
        UTIL_ASSERT(MXC_FLC_Write(LOCKOUT_STATE_ADDR, sizeof(tmp), &tmp) == SUCCESS_RETURN);
    }

    _defense_lockout_proc();
}
