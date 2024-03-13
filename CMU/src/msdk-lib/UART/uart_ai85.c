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

#include "uart.h"
#include "mxc_device.h"
#include "mxc_pins.h"
#include "mxc_assert.h"
#include "uart_revb.h"
#include "uart_common.h"
#include "lpgcr_regs.h"

int MXC_UART_Init(mxc_uart_regs_t *uart, unsigned int baud, mxc_uart_clock_t clock)
{
    int retval;

    retval = MXC_UART_Shutdown(uart);

    if (retval) {
        return retval;
    }

    switch (clock) {
    case MXC_UART_ERTCO_CLK:
        MXC_SYS_ClockSourceEnable(MXC_SYS_CLOCK_ERTCO);
        break;

    case MXC_UART_IBRO_CLK:
        MXC_SYS_ClockSourceEnable(MXC_SYS_CLOCK_IBRO);
        break;

    default:
        break;
    }

    switch (MXC_UART_GET_IDX(uart)) {
    case 0:
        MXC_GPIO_Config(&gpio_cfg_uart0);
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_UART0);
        break;

    case 1:
        MXC_GPIO_Config(&gpio_cfg_uart1);
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_UART1);
        break;

    case 2:
        MXC_GPIO_Config(&gpio_cfg_uart2);
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_UART2);
        break;

    case 3:
        MXC_GPIO_Config(&gpio_cfg_uart3);
        MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_UART3);
        break;

    default:
        return E_BAD_PARAM;
    }

    return MXC_UART_RevB_Init((mxc_uart_revb_regs_t *)uart, baud, clock);
}

int MXC_UART_Shutdown(mxc_uart_regs_t *uart)
{
    switch (MXC_UART_GET_IDX(uart)) {
    case 0:
        MXC_SYS_Reset_Periph(MXC_SYS_RESET0_UART0);
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_UART0);
        break;

    case 1:
        MXC_SYS_Reset_Periph(MXC_SYS_RESET0_UART1);
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_UART1);
        break;

    case 2:
        MXC_SYS_Reset_Periph(MXC_SYS_RESET0_UART2);
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_UART2);
        break;

    case 3:
        MXC_SYS_Reset_Periph(MXC_SYS_RESET_UART3);
        MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_UART3);
        break;

    default:
        return E_BAD_PARAM;
    }

    return E_NO_ERROR;
}

int MXC_UART_SetFrequency(mxc_uart_regs_t *uart, unsigned int baud, mxc_uart_clock_t clock)
{
    int frequency, clkDiv = 0, mod = 0;
    if (MXC_UART_GET_IDX(uart) < 0) {
        return E_BAD_PARAM;
    }

    // check if the uart is LPUART
    if (uart == MXC_UART3) {
        // OSR default value
        uart->osr = 5;

        switch (clock) {
        case MXC_UART_APB_CLK:
        case MXC_UART_IBRO_CLK:
            clkDiv = ((IBRO_FREQ) / baud);
            mod = ((IBRO_FREQ) % baud);
            break;

        case MXC_UART_ERTCO_CLK:
            uart->ctrl |= MXC_S_UART_CTRL_BCLKSRC_EXTERNAL_CLOCK;
            uart->ctrl |= MXC_F_UART_CTRL_FDM;
            clkDiv = ((ERTCO_FREQ * 2) / baud);
            mod = ((ERTCO_FREQ * 2) % baud);

            if (baud > 2400) {
                uart->osr = 0;
            } else {
                uart->osr = 1;
            }
            break;

        default:
            return E_BAD_PARAM;
        }
        if (!clkDiv || mod > (baud / 2)) {
            clkDiv++;
        }
        uart->clkdiv = clkDiv;
        frequency = MXC_UART_GetFrequency(uart);
    } else {
        if (clock == MXC_UART_ERTCO_CLK) {
            return E_BAD_PARAM;
        }

        frequency = MXC_UART_RevB_SetFrequency((mxc_uart_revb_regs_t *)uart, baud, clock);
    }

    if (frequency > 0) {
        // Enable baud clock and wait for it to become ready.
        uart->ctrl |= MXC_F_UART_CTRL_BCLKEN;
        while (((uart->ctrl & MXC_F_UART_CTRL_BCLKRDY) >> MXC_F_UART_CTRL_BCLKRDY_POS) == 0) {}
    }

    return frequency;
}

int MXC_UART_GetFrequency(mxc_uart_regs_t *uart)
{
    int periphClock = 0;

    if (MXC_UART_GET_IDX(uart) < 0) {
        return E_BAD_PARAM;
    }

    // check if UARt is LP UART
    if (uart == MXC_UART3) {
        if ((uart->ctrl & MXC_F_UART_CTRL_BCLKSRC) == MXC_S_UART_CTRL_BCLKSRC_EXTERNAL_CLOCK) {
            periphClock = ERTCO_FREQ * 2;
        } else if ((uart->ctrl & MXC_F_UART_CTRL_BCLKSRC) ==
                   MXC_S_UART_CTRL_BCLKSRC_PERIPHERAL_CLOCK) {
            periphClock = IBRO_FREQ;
        } else {
            return E_BAD_PARAM;
        }
        return (periphClock / uart->clkdiv);
    } else {
        return MXC_UART_RevB_GetFrequency((mxc_uart_revb_regs_t *)uart);
    }
}

int MXC_UART_SetDataSize(mxc_uart_regs_t *uart, int dataSize)
{
    return MXC_UART_RevB_SetDataSize((mxc_uart_revb_regs_t *)uart, dataSize);
}

int MXC_UART_SetStopBits(mxc_uart_regs_t *uart, mxc_uart_stop_t stopBits)
{
    return MXC_UART_RevB_SetStopBits((mxc_uart_revb_regs_t *)uart, stopBits);
}

int MXC_UART_SetParity(mxc_uart_regs_t *uart, mxc_uart_parity_t parity)
{
    return MXC_UART_RevB_SetParity((mxc_uart_revb_regs_t *)uart, parity);
}

int MXC_UART_ReadCharacterRaw(mxc_uart_regs_t *uart)
{
    return MXC_UART_RevB_ReadCharacterRaw((mxc_uart_revb_regs_t *)uart);
}

int MXC_UART_WriteCharacterRaw(mxc_uart_regs_t *uart, uint8_t character)
{
    return MXC_UART_RevB_WriteCharacterRaw((mxc_uart_revb_regs_t *)uart, character);
}

int MXC_UART_ReadCharacter(mxc_uart_regs_t *uart)
{
    return MXC_UART_Common_ReadCharacter(uart);
}

int MXC_UART_WriteCharacter(mxc_uart_regs_t *uart, uint8_t character)
{
    return MXC_UART_Common_WriteCharacter(uart, character);
}

unsigned int MXC_UART_GetRXFIFOAvailable(mxc_uart_regs_t *uart)
{
    return MXC_UART_RevB_GetRXFIFOAvailable((mxc_uart_revb_regs_t *)uart);
}

unsigned int MXC_UART_GetTXFIFOAvailable(mxc_uart_regs_t *uart)
{
    return MXC_UART_RevB_GetTXFIFOAvailable((mxc_uart_revb_regs_t *)uart);
}

int MXC_UART_SetRXThreshold(mxc_uart_regs_t *uart, unsigned int numBytes)
{
    return MXC_UART_RevB_SetRXThreshold((mxc_uart_revb_regs_t *)uart, numBytes);
}

int MXC_UART_SetTXThreshold(mxc_uart_regs_t *uart, unsigned int numBytes)
{
    return E_NOT_SUPPORTED;
}
