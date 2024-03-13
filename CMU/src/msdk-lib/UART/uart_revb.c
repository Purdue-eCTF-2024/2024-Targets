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

#include <stdio.h>
#include "mxc_device.h"
#include "mxc_assert.h"
#include "uart.h"
#include "uart_revb.h"

/* **** Definitions **** */
#define MXC_UART_REVB_ERRINT_EN \
    (MXC_F_UART_REVB_INT_EN_RX_FERR | MXC_F_UART_REVB_INT_EN_RX_PAR | MXC_F_UART_REVB_INT_EN_RX_OV)

#define MXC_UART_REVB_ERRINT_FL \
    (MXC_F_UART_REVB_INT_FL_RX_FERR | MXC_F_UART_REVB_INT_FL_RX_PAR | MXC_F_UART_REVB_INT_FL_RX_OV)

/* **** Variable Declaration **** */
typedef struct {
    mxc_uart_revb_req_t *req;
    int channelTx;
    int channelRx;
} uart_revb_req_state_t;

uart_revb_req_state_t states[MXC_UART_INSTANCES];

/* **** Function Prototypes **** */

/* ************************************************************************* */
/* Control/Configuration functions                                           */
/* ************************************************************************* */
int MXC_UART_RevB_Init(mxc_uart_revb_regs_t *uart, unsigned int baud, mxc_uart_revb_clock_t clock)
{
    int err;

    if (MXC_UART_GET_IDX((mxc_uart_regs_t *)uart) < 0) {
        return E_BAD_PARAM;
    }

    // Initialize UART
    if ((err = MXC_UART_SetRXThreshold((mxc_uart_regs_t *)uart, 1)) !=
        E_NO_ERROR) { // Set RX threshold to 1 byte
        return err;
    }

    if ((err = MXC_UART_SetDataSize((mxc_uart_regs_t *)uart, 8)) !=
        E_NO_ERROR) { // Set Datasize to 8 bits
        return err;
    }

    if ((err = MXC_UART_SetParity((mxc_uart_regs_t *)uart, MXC_UART_PARITY_DISABLE)) !=
        E_NO_ERROR) {
        return err;
    }

    if ((err = MXC_UART_SetStopBits((mxc_uart_regs_t *)uart, MXC_UART_STOP_1)) != E_NO_ERROR) {
        return err;
    }

    if ((err = MXC_UART_SetFrequency((mxc_uart_regs_t *)uart, baud, (mxc_uart_clock_t)clock)) <
        E_NO_ERROR) {
        return err;
    }

    return E_NO_ERROR;
}

int MXC_UART_RevB_SetFrequency(mxc_uart_revb_regs_t *uart, unsigned int baud,
                               mxc_uart_revb_clock_t clock)
{
    unsigned clkDiv = 0, mod = 0;
    if (MXC_UART_GET_IDX((mxc_uart_regs_t *)uart) < 0) {
        return E_BAD_PARAM;
    }

    // OSR default value
    uart->osr = 5;

    switch (clock) {
    case MXC_UART_REVB_APB_CLK:
        clkDiv = (PeripheralClock / baud);
        mod = (PeripheralClock % baud);
        break;

    case MXC_UART_REVB_EXT_CLK:
        uart->ctrl |= MXC_S_UART_REVB_CTRL_BCLKSRC_EXTERNAL_CLOCK;
        clkDiv = UART_EXTCLK_FREQ / baud;
        mod = UART_EXTCLK_FREQ % baud;
        break;

    //case MXC_UART_IBRO_CLK:
    case MXC_UART_REVB_CLK2:
        clkDiv = (IBRO_FREQ / baud);
        mod = (IBRO_FREQ % baud);

        uart->ctrl |= MXC_S_UART_REVB_CTRL_BCLKSRC_CLK2;
        break;

    //case MXC_UART_ERFO:
    case MXC_UART_REVB_CLK3:
#if (TARGET_NUM == 78000 || TARGET_NUM == 78002)
        return E_BAD_PARAM;
#else
        clkDiv = (ERFO_FREQ / baud);
        mod = (ERFO_FREQ % baud);
#endif

        uart->ctrl |= MXC_S_UART_REVB_CTRL_BCLKSRC_CLK3;
        break;

    default:
        return E_BAD_PARAM;
    }

    if (!clkDiv || mod > (baud / 2)) {
        clkDiv++;
    }
    uart->clkdiv = clkDiv;
    return MXC_UART_GetFrequency((mxc_uart_regs_t *)uart);
}

int MXC_UART_RevB_GetFrequency(mxc_uart_revb_regs_t *uart)
{
    int periphClock = 0;

    if (MXC_UART_GET_IDX((mxc_uart_regs_t *)uart) < 0) {
        return E_BAD_PARAM;
    }

    if ((uart->ctrl & MXC_F_UART_REVB_CTRL_BCLKSRC) ==
        MXC_S_UART_REVB_CTRL_BCLKSRC_EXTERNAL_CLOCK) {
        periphClock = UART_EXTCLK_FREQ;
    } else if ((uart->ctrl & MXC_F_UART_REVB_CTRL_BCLKSRC) ==
               MXC_S_UART_REVB_CTRL_BCLKSRC_PERIPHERAL_CLOCK) {
        periphClock = PeripheralClock;
    } else if ((uart->ctrl & MXC_F_UART_REVB_CTRL_BCLKSRC) == MXC_S_UART_REVB_CTRL_BCLKSRC_CLK2) {
        periphClock = IBRO_FREQ;
    } else if ((uart->ctrl & MXC_F_UART_REVB_CTRL_BCLKSRC) == MXC_S_UART_REVB_CTRL_BCLKSRC_CLK3) {
#if (TARGET_NUM == 78000 || TARGET_NUM == 78002)
        return E_BAD_PARAM;
#else
        periphClock = ERFO_FREQ;
#endif
    } else {
        return E_BAD_PARAM;
    }

    return (periphClock / uart->clkdiv);
}

int MXC_UART_RevB_SetDataSize(mxc_uart_revb_regs_t *uart, int dataSize)
{
    if (MXC_UART_GET_IDX((mxc_uart_regs_t *)uart) < 0) {
        return E_BAD_PARAM;
    }

    if (dataSize < 5 || dataSize > 8) {
        return E_BAD_PARAM;
    }

    dataSize = (dataSize - 5) << MXC_F_UART_REVB_CTRL_CHAR_SIZE_POS;

    MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_CHAR_SIZE, dataSize);

    return E_NO_ERROR;
}

int MXC_UART_RevB_SetStopBits(mxc_uart_revb_regs_t *uart, mxc_uart_stop_t stopBits)
{
    if (MXC_UART_GET_IDX((mxc_uart_regs_t *)uart) < 0) {
        return E_BAD_PARAM;
    }

    switch (stopBits) {
    case MXC_UART_STOP_1:
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_STOPBITS,
                     0 << MXC_F_UART_REVB_CTRL_STOPBITS_POS);
        break;

    case MXC_UART_STOP_2:
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_STOPBITS,
                     1 << MXC_F_UART_REVB_CTRL_STOPBITS_POS);
        break;

    default:
        return E_BAD_PARAM;
        break;
    }

    return E_NO_ERROR;
}

int MXC_UART_RevB_SetParity(mxc_uart_revb_regs_t *uart, mxc_uart_parity_t parity)
{
    if (MXC_UART_GET_IDX((mxc_uart_regs_t *)uart) < 0) {
        return E_BAD_PARAM;
    }

    switch (parity) {
    case MXC_UART_PARITY_DISABLE:
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_EN, 0 << MXC_F_UART_REVB_CTRL_PAR_EN_POS);
        break;

    case MXC_UART_PARITY_EVEN_0:
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_EN, 1 << MXC_F_UART_REVB_CTRL_PAR_EN_POS);
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_EO, 0 << MXC_F_UART_REVB_CTRL_PAR_EO_POS);
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_MD, 0 << MXC_F_UART_REVB_CTRL_PAR_MD_POS);
        break;

    case MXC_UART_PARITY_EVEN_1:
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_EN, 1 << MXC_F_UART_REVB_CTRL_PAR_EN_POS);
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_EO, 0 << MXC_F_UART_REVB_CTRL_PAR_EO_POS);
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_MD, 1 << MXC_F_UART_REVB_CTRL_PAR_MD_POS);
        break;

    case MXC_UART_PARITY_ODD_0:
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_EN, 1 << MXC_F_UART_REVB_CTRL_PAR_EN_POS);
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_EO, 1 << MXC_F_UART_REVB_CTRL_PAR_EO_POS);
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_MD, 0 << MXC_F_UART_REVB_CTRL_PAR_MD_POS);
        break;

    case MXC_UART_PARITY_ODD_1:
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_EN, 1 << MXC_F_UART_REVB_CTRL_PAR_EN_POS);
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_EO, 1 << MXC_F_UART_REVB_CTRL_PAR_EO_POS);
        MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_PAR_MD, 1 << MXC_F_UART_REVB_CTRL_PAR_MD_POS);
        break;

    default:
        return E_BAD_PARAM;
        break;
    }

    return E_NO_ERROR;
}

int MXC_UART_RevB_GetActive(mxc_uart_revb_regs_t *uart)
{
    if (MXC_UART_GET_IDX((mxc_uart_regs_t *)uart) < 0) {
        return E_BAD_PARAM;
    }

    if (uart->status & (MXC_F_UART_REVB_STATUS_TX_BUSY | MXC_F_UART_REVB_STATUS_RX_BUSY)) {
        return E_BUSY;
    }

    return E_NO_ERROR;
}

int MXC_UART_RevB_ReadCharacterRaw(mxc_uart_revb_regs_t *uart)
{
    if (MXC_UART_GET_IDX((mxc_uart_regs_t *)uart) < 0) {
        return E_BAD_PARAM;
    }

    if (uart->status & MXC_F_UART_REVB_STATUS_RX_EM) {
        return E_UNDERFLOW;
    }

    return uart->fifo;
}

int MXC_UART_RevB_WriteCharacterRaw(mxc_uart_revb_regs_t *uart, uint8_t character)
{
    if (MXC_UART_GET_IDX((mxc_uart_regs_t *)uart) < 0) {
        return E_BAD_PARAM;
    }

    // Require the TX FIFO to be empty, so that we write out the expected character
    // Return error if the FIFO is full
    if (uart->status & MXC_F_UART_REVB_STATUS_TX_FULL) {
        return E_OVERFLOW;
    }

    uart->fifo = character;

    return E_NO_ERROR;
}

int MXC_UART_RevB_ReadCharacter(mxc_uart_revb_regs_t *uart)
{
    if (MXC_UART_GET_IDX((mxc_uart_regs_t *)uart) < 0) {
        return E_BAD_PARAM;
    }

    if (uart->status & MXC_F_UART_REVB_STATUS_RX_EM) {
        return E_UNDERFLOW;
    }

    return uart->fifo;
}

int MXC_UART_RevB_WriteCharacter(mxc_uart_revb_regs_t *uart, uint8_t character)
{
    if (MXC_UART_GET_IDX((mxc_uart_regs_t *)uart) < 0) {
        return E_BAD_PARAM;
    }

    // Require the TX FIFO to be empty, so that we write out the expected character
    // Return error if the FIFO is full
    if (uart->status & MXC_F_UART_REVB_STATUS_TX_FULL) {
        return E_OVERFLOW;
    }

    uart->fifo = character;

    return E_NO_ERROR;
}

unsigned int MXC_UART_RevB_GetRXFIFOAvailable(mxc_uart_revb_regs_t *uart)
{
    return (uart->status & MXC_F_UART_REVB_STATUS_RX_LVL) >> MXC_F_UART_REVB_STATUS_RX_LVL_POS;
}

unsigned int MXC_UART_RevB_GetTXFIFOAvailable(mxc_uart_revb_regs_t *uart)
{
    int txCnt = (uart->status & MXC_F_UART_REVB_STATUS_TX_LVL) >> MXC_F_UART_REVB_STATUS_TX_LVL_POS;
    return MXC_UART_FIFO_DEPTH - txCnt;
}

int MXC_UART_RevB_SetRXThreshold(mxc_uart_revb_regs_t *uart, unsigned int numBytes)
{
    if (MXC_UART_GET_IDX((mxc_uart_regs_t *)uart) < 0) {
        return E_BAD_PARAM;
    }

    if (numBytes < 1 || numBytes > MXC_UART_FIFO_DEPTH) {
        return E_BAD_PARAM;
    }

    numBytes <<= MXC_F_UART_REVB_CTRL_RX_THD_VAL_POS;
    MXC_SETFIELD(uart->ctrl, MXC_F_UART_REVB_CTRL_RX_THD_VAL, numBytes);

    return E_NO_ERROR;
}

