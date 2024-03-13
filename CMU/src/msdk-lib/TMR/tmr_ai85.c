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

#include "tmr.h"
#include "tmr_revb.h"
#include "lpgcr_regs.h"
#include "stdbool.h"

int MXC_TMR_Init(mxc_tmr_regs_t *tmr, mxc_tmr_cfg_t *cfg, bool init_pins)
{
    int tmr_id = MXC_TMR_GET_IDX(tmr);
    uint8_t clockSource = MXC_TMR_CLK0;

    if (cfg == NULL) {
        return E_NULL_PTR;
    }

    MXC_ASSERT(tmr_id >= 0);

    switch (cfg->clock) {
    case MXC_TMR_60M_CLK:
        if (tmr_id > 3) { // Timers 4-5 do not support this clock source
            return E_NOT_SUPPORTED;
        }

        clockSource = MXC_TMR_CLK1;
        MXC_SYS_ClockSourceEnable(MXC_SYS_CLOCK_ISO);
        MXC_TMR_RevB_SetClockSourceFreq((mxc_tmr_revb_regs_t *)tmr, ISO_FREQ);
        break;

    case MXC_TMR_8M_CLK:
        if (tmr_id > 3) {
            clockSource = MXC_TMR_CLK0;
        } else {
            clockSource = MXC_TMR_CLK2;
        }

        MXC_SYS_ClockSourceEnable(MXC_SYS_CLOCK_IBRO);
        MXC_TMR_RevB_SetClockSourceFreq((mxc_tmr_revb_regs_t *)tmr, IBRO_FREQ);
        break;

    case MXC_TMR_32K_CLK:
        if (tmr_id == 4) {
            clockSource = MXC_TMR_CLK1;
        } else if (tmr_id < 4) {
            clockSource = MXC_TMR_CLK3;
        } else { // Timer 5 does not support this clock source
            return E_NOT_SUPPORTED;
        }

        MXC_SYS_ClockSourceEnable(MXC_SYS_CLOCK_ERTCO);
        MXC_TMR_RevB_SetClockSourceFreq((mxc_tmr_revb_regs_t *)tmr, ERTCO_FREQ);
        break;

    case MXC_TMR_8K_CLK:
        if (tmr_id < 4) { // Timers 0-3 do not support this clock source
            return E_NOT_SUPPORTED;
        }

        clockSource = MXC_TMR_CLK2;
        MXC_SYS_ClockSourceEnable(MXC_SYS_CLOCK_INRO);
        MXC_TMR_RevB_SetClockSourceFreq((mxc_tmr_revb_regs_t *)tmr, INRO_FREQ);
        break;

    // IBRO/8
    case MXC_TMR_8M_DIV8_CLK:
        if (tmr_id != 5) { // Only Timer 5 supports this clock source divide
            return E_NOT_SUPPORTED;
        }

        clockSource = MXC_TMR_CLK1;
        MXC_SYS_ClockSourceEnable(MXC_SYS_CLOCK_IBRO);
        MXC_TMR_RevB_SetClockSourceFreq((mxc_tmr_revb_regs_t *)tmr, (IBRO_FREQ / 8));
        break;

    default:
        // PCLK
        MXC_TMR_RevB_SetClockSourceFreq((mxc_tmr_revb_regs_t *)tmr, PeripheralClock);
        break;
    }

    //enable peripheral clock and configure gpio pins
    switch (tmr_id) {
    case 0:
        MXC_SYS_Reset_Periph(MXC_SYS_RESET0_TMR0);
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_TMR0);

        if (init_pins) {
            if (cfg->bitMode != TMR_BIT_MODE_16B) {
                MXC_GPIO_Config(&gpio_cfg_tmr0);
            } else {
                MXC_GPIO_Config(&gpio_cfg_tmr0b);
            }
        }

        break;

    case 1:
        MXC_SYS_Reset_Periph(MXC_SYS_RESET0_TMR1);
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_TMR1);

        if (init_pins) {
            if (cfg->bitMode != TMR_BIT_MODE_16B) {
                MXC_GPIO_Config(&gpio_cfg_tmr1);
            } else {
                MXC_GPIO_Config(&gpio_cfg_tmr1b);
            }
        }

        break;

    case 2:
        MXC_SYS_Reset_Periph(MXC_SYS_RESET0_TMR2);
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_TMR2);

        if (init_pins) {
            if (cfg->bitMode != TMR_BIT_MODE_16B) {
                MXC_GPIO_Config(&gpio_cfg_tmr2);
            } else {
                MXC_GPIO_Config(&gpio_cfg_tmr2b);
            }
        }

        break;

    case 3:
        MXC_SYS_Reset_Periph(MXC_SYS_RESET0_TMR3);
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_TMR3);

        if (init_pins) {
            if (cfg->bitMode != TMR_BIT_MODE_16B) {
                MXC_GPIO_Config(&gpio_cfg_tmr3);
            } else {
                MXC_GPIO_Config(&gpio_cfg_tmr3b);
            }
        }

        break;

    case 4:
        MXC_GPIO_Config(&gpio_cfg_tmr4);
        MXC_SYS_Reset_Periph(MXC_SYS_RESET_TMR4);
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_TMR4);
        break;

    case 5:
        MXC_GPIO_Config(&gpio_cfg_tmr5);
        MXC_SYS_Reset_Periph(MXC_SYS_RESET_TMR5);
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_TMR5);
        break;
    }

    return MXC_TMR_RevB_Init((mxc_tmr_revb_regs_t *)tmr, cfg, clockSource);
}

void MXC_TMR_Shutdown(mxc_tmr_regs_t *tmr)
{
    MXC_ASSERT(MXC_TMR_GET_IDX(tmr) >= 0);

    MXC_TMR_RevB_Shutdown((mxc_tmr_revb_regs_t *)tmr);

    // System settigns
    //diasble peripheral clock
    if (tmr == MXC_TMR0) {
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_TMR0);
    }

    if (tmr == MXC_TMR1) {
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_TMR1);
    }

    if (tmr == MXC_TMR2) {
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_TMR2);
    }

    if (tmr == MXC_TMR3) {
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_TMR3);
    }

    if (tmr == MXC_TMR4) {
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_TMR4);
    }

    if (tmr == MXC_TMR5) {
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_TMR5);
    }
}

void MXC_TMR_Start(mxc_tmr_regs_t *tmr)
{
    MXC_TMR_RevB_Start((mxc_tmr_revb_regs_t *)tmr);
}

