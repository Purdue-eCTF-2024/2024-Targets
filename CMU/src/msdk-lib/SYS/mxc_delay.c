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
#include <stdint.h>
#include <stddef.h>
#include "mxc_device.h"
#include "mxc_delay.h"
#include "mxc_sys.h"

#ifdef __riscv

int MXC_Delay(uint32_t us)
{
    // Check if there is nothing to do
    if (us == 0) {
        return E_NO_ERROR;
    }

    // Calculate number of cycles needed.
    uint32_t ticks = (MXC_SYS_RiscVClockRate() / 1000000) * us;

    CSR_SetPCMR(0); // Turn off counter
    CSR_SetPCCR(0); // Clear counter register
    CSR_SetPCER(1); // Enable counting of cycles
    CSR_SetPCMR(3); // Turn on counter

    while (CSR_GetPCCR() < ticks) {
        // Wait for counter to reach the tick count.
    }
    return E_NO_ERROR;
}

#else

/* ************************************************************************** */

__attribute__((section(".flashprog")))
__attribute__((aligned(128))) // just to really make sure it's aligned
int MXC_DelayTicks(uint32_t ticks)
{
    volatile uint32_t i = 0;
    for (; i < ticks; ++i);

    return E_NO_ERROR;
}

__attribute__((section(".flashprog")))
__attribute__((aligned(64))) // just to really make sure it's aligned
int MXC_Delay(uint32_t us)
{
    // Clamp to 100 seconds maximum
    if (us > 100000000) {
        us = 100000000;
    }

    // Approximately 3 iterations per microsecond
    uint32_t ticks = (us * 30) / 10;

    return MXC_DelayTicks(ticks);
}

#endif // __riscv
