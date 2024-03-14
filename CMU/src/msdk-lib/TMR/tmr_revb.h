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

#ifndef LIBRARIES_PERIPHDRIVERS_SOURCE_TMR_TMR_REVB_H_
#define LIBRARIES_PERIPHDRIVERS_SOURCE_TMR_TMR_REVB_H_

/* **** Includes **** */
#include <stddef.h>
#include "mxc_assert.h"
#include "tmr.h"
#include "gpio.h"
#include "mxc_pins.h"
#include "tmr_revb_regs.h"

typedef enum {
    MXC_TMR_CLK0,
    MXC_TMR_CLK1,
    MXC_TMR_CLK2,
    MXC_TMR_CLK3,
} mxc_tmr_clksel_t;

/* **** Functions **** */
int MXC_TMR_RevB_Init(mxc_tmr_revb_regs_t *tmr, mxc_tmr_cfg_t *cfg, uint8_t clk_src);
void MXC_TMR_RevB_SetClockSourceFreq(mxc_tmr_revb_regs_t *tmr, int clksrc_freq);
void MXC_TMR_RevB_ConfigGeneric(mxc_tmr_revb_regs_t *tmr, mxc_tmr_cfg_t *cfg);
void MXC_TMR_RevB_Shutdown(mxc_tmr_revb_regs_t *tmr);
void MXC_TMR_RevB_Start(mxc_tmr_revb_regs_t *tmr);

#endif // LIBRARIES_PERIPHDRIVERS_SOURCE_TMR_TMR_REVB_H_