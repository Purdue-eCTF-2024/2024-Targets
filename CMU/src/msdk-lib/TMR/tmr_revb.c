/******************************************************************************
 * Copyright (C) 2023 Maxim Integrated Products, Inc., All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL MAXIM INTEGRATED BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name of Maxim Integrated
 * Products, Inc. shall not be used except as stated in the Maxim Integrated
 * Products, Inc. Branding Policy.
 *
 * The mere transfer of this software does not imply any licenses
 * of trade secrets, proprietary technology, copyrights, patents,
 * trademarks, maskwork rights, or any other form of intellectual
 * property whatsoever. Maxim Integrated Products, Inc. retains all
 * ownership rights.
 *
 ******************************************************************************/

/* **** Includes **** */
#include <stddef.h>
#include <stdbool.h>
#include "mxc_assert.h"
#include "tmr.h"
#include "tmr_revb.h"
#include "gpio.h"
#include "mxc_pins.h"

/* **** Definitions **** */
#define TIMER_16A_OFFSET 0
#define TIMER_16B_OFFSET 16

typedef struct {
    bool configured;
    uint32_t freq;
} mxc_tmr_revb_clksrc_freq_t;

static mxc_tmr_revb_clksrc_freq_t tmr_clksrc[MXC_CFG_TMR_INSTANCES];

/* **** Functions **** */
int MXC_TMR_RevB_Init(mxc_tmr_revb_regs_t *tmr, mxc_tmr_cfg_t *cfg, uint8_t clk_src)
{
    int tmr_id = MXC_TMR_GET_IDX((mxc_tmr_regs_t *)tmr);
    (void)tmr_id;
    MXC_ASSERT(tmr_id >= 0);

    if (cfg == NULL) {
        return E_NULL_PTR;
    }

    uint32_t timerOffset;

    if (cfg->bitMode == TMR_BIT_MODE_16B) {
        timerOffset = TIMER_16B_OFFSET;
    } else {
        timerOffset = TIMER_16A_OFFSET;
    }

    // Default 32 bit timer
    if (cfg->bitMode & (TMR_BIT_MODE_16A | TMR_BIT_MODE_16B)) {
        tmr->ctrl1 &= ~MXC_F_TMR_REVB_CTRL1_CASCADE;
    } else {
        tmr->ctrl1 |= MXC_F_TMR_REVB_CTRL1_CASCADE;
    }

    // Clear interrupt flag
    tmr->intfl |= (MXC_F_TMR_REVB_INTFL_IRQ_A | MXC_F_TMR_REVB_INTFL_IRQ_B);

    // Set the prescale
    tmr->ctrl0 |= (cfg->pres << timerOffset);

    // Select clock Source
    tmr->ctrl1 |= ((clk_src << MXC_F_TMR_REVB_CTRL1_CLKSEL_A_POS) << timerOffset);

    //TIMER_16B only supports compare, oneshot and continuous modes.
    switch (cfg->mode) {
    case TMR_MODE_ONESHOT:
        MXC_TMR_RevB_ConfigGeneric((mxc_tmr_revb_regs_t *)tmr, cfg);
        break;

    case TMR_MODE_CONTINUOUS:
        MXC_TMR_RevB_ConfigGeneric((mxc_tmr_revb_regs_t *)tmr, cfg);
        break;

    case TMR_MODE_COUNTER:
        if (cfg->bitMode == TMR_BIT_MODE_16B) {
            return E_NOT_SUPPORTED;
        }

        MXC_TMR_RevB_ConfigGeneric(tmr, cfg);
        break;

    case TMR_MODE_CAPTURE:
        if (cfg->bitMode == TMR_BIT_MODE_16B) {
            return E_NOT_SUPPORTED;
        }

        MXC_TMR_RevB_ConfigGeneric(tmr, cfg);
        break;

    case TMR_MODE_COMPARE:
        MXC_TMR_RevB_ConfigGeneric((mxc_tmr_revb_regs_t *)tmr, cfg);
        break;

    case TMR_MODE_GATED:
        if (cfg->bitMode == TMR_BIT_MODE_16B) {
            return E_NOT_SUPPORTED;
        }

        MXC_TMR_RevB_ConfigGeneric(tmr, cfg);
        break;

    case TMR_MODE_CAPTURE_COMPARE:
        if (cfg->bitMode == TMR_BIT_MODE_16B) {
            return E_NOT_SUPPORTED;
        }

        MXC_TMR_RevB_ConfigGeneric(tmr, cfg);
        break;

    case TMR_MODE_PWM:
        if (cfg->bitMode == TMR_BIT_MODE_16B) {
            return E_NOT_SUPPORTED;
        }

        MXC_TMR_RevB_ConfigGeneric((mxc_tmr_revb_regs_t *)tmr, cfg);
        break;
    }

    return E_NO_ERROR;
}

void MXC_TMR_RevB_SetClockSourceFreq(mxc_tmr_revb_regs_t *tmr, int clksrc_freq)
{
    int tmr_id = MXC_TMR_GET_IDX((mxc_tmr_regs_t *)tmr);
    (void)tmr_id;
    MXC_ASSERT(tmr_id >= 0);

    tmr_clksrc[tmr_id].configured = true;
    tmr_clksrc[tmr_id].freq = clksrc_freq;
}

void MXC_TMR_RevB_ConfigGeneric(mxc_tmr_revb_regs_t *tmr, mxc_tmr_cfg_t *cfg)
{
    uint32_t timerOffset;
    int tmr_id = MXC_TMR_GET_IDX((mxc_tmr_regs_t *)tmr);
    (void)tmr_id;
    MXC_ASSERT(tmr_id >= 0);

    if (cfg == NULL) {
        return;
    }

    if (cfg->bitMode == TMR_BIT_MODE_16B) {
        timerOffset = TIMER_16B_OFFSET;
    } else {
        timerOffset = TIMER_16A_OFFSET;
    }

    tmr->ctrl0 |= (MXC_F_TMR_REVB_CTRL0_CLKEN_A << timerOffset);
    while (!(tmr->ctrl1 & (MXC_F_TMR_REVB_CTRL1_CLKRDY_A << timerOffset))) {}

    tmr->ctrl0 |= (cfg->mode << timerOffset);
    tmr->ctrl0 |= ((cfg->pol << MXC_F_TMR_REVB_CTRL0_POL_A_POS) << timerOffset);
    //enable timer interrupt if needed
    tmr->cnt = (0x1 << timerOffset);
    while (!(tmr->intfl & (MXC_F_TMR_REVB_INTFL_WRDONE_A << timerOffset))) {}

    tmr->cmp = (cfg->cmp_cnt << timerOffset);
#if TARGET_NUM == 32655 || TARGET_NUM == 78000 || TARGET_NUM == 32690 || TARGET_NUM == 78002
    tmr->ctrl1 &= ~(MXC_F_TMR_REVB_CTRL1_OUTEN_A << timerOffset);
#else
    tmr->ctrl1 |= (MXC_F_TMR_REVB_CTRL1_OUTEN_A << timerOffset);
#endif

    // If configured as TIMER_16B then enable the interrupt and start the timer
    if (cfg->bitMode == TMR_BIT_MODE_16B) {
        tmr->ctrl1 |= MXC_F_TMR_REVB_CTRL1_IE_B;

        tmr->ctrl0 |= MXC_F_TMR_REVB_CTRL0_EN_B;
        while (!(tmr->ctrl1 & MXC_F_TMR_REVB_CTRL1_CLKEN_B)) {}
    }
}

void MXC_TMR_RevB_Shutdown(mxc_tmr_revb_regs_t *tmr)
{
    int tmr_id = MXC_TMR_GET_IDX((mxc_tmr_regs_t *)tmr);
    (void)tmr_id;
    MXC_ASSERT(tmr_id >= 0);

    // Disable timer and clear settings
    tmr->ctrl0 = 0;
    while (tmr->ctrl1 & MXC_F_TMR_REVB_CTRL1_CLKRDY_A) {}
    tmr_clksrc[tmr_id].configured = false;
}

void MXC_TMR_RevB_Start(mxc_tmr_revb_regs_t *tmr)
{
    int tmr_id = MXC_TMR_GET_IDX((mxc_tmr_regs_t *)tmr);
    (void)tmr_id;
    MXC_ASSERT(tmr_id >= 0);

    tmr->ctrl0 |= MXC_F_TMR_REVB_CTRL0_EN_A;
    while (!(tmr->ctrl1 & MXC_F_TMR_REVB_CTRL1_CLKEN_A)) {}
}

