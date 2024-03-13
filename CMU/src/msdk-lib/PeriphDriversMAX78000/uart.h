/**
 * @file    uart.h
 * @brief   Serial Peripheral Interface (UART) communications driver.
 */

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

/* Define to prevent redundant inclusion */
#ifndef LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX78000_UART_H_
#define LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX78000_UART_H_

/***** Definitions *****/
#include "uart_regs.h"
#include "mxc_sys.h"

#define UART_EXTCLK_FREQ EXTCLK_FREQ

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup uart UART
 * @ingroup periphlibs
 * @{
 */

typedef struct _mxc_uart_req_t mxc_uart_req_t;
/**
 * @brief   The list of UART stop bit lengths supported
 * 
 */
typedef enum {
    MXC_UART_STOP_1, ///< UART Stop 1 clock cycle
    MXC_UART_STOP_2, ///< UART Stop 2 clock cycle (1.5 clocks for 5 bit characters)
} mxc_uart_stop_t;

/**
 * @brief   The list of UART Parity options supported
 * 
 */
typedef enum {
    MXC_UART_PARITY_DISABLE, ///< UART Parity Disabled
    MXC_UART_PARITY_EVEN_0, ///< UART Parity Even, 0 based
    MXC_UART_PARITY_EVEN_1, ///< UART Parity Even, 1 based
    MXC_UART_PARITY_ODD_0, ///< UART Parity Odd, 0 based
    MXC_UART_PARITY_ODD_1, ///< UART Parity Odd, 1 based
} mxc_uart_parity_t;

/**
 * @brief   The list of UART flow control options supported
 * 
 */
typedef enum {
    MXC_UART_FLOW_DIS, ///< UART Flow Control Disabled
    MXC_UART_FLOW_EN, ///< UART Flow Control Enabled
} mxc_uart_flow_t;

/**
 * @brief      Clock settings */
typedef enum {
    /*For UART3 APB clock source is the 8MHz clock*/
    MXC_UART_APB_CLK = 0,
    /*IBRO clock can only be used for UART 0, 1 & 2*/
    MXC_UART_IBRO_CLK = 2,
    /*ERTCO clock can only be used for UART3*/
    MXC_UART_ERTCO_CLK = 4,
} mxc_uart_clock_t;

/**
 * @brief   The callback routine used to indicate the transaction has terminated.
 *
 * @param   req          The details of the transaction.
 * @param   result       See \ref MXC_Error_Codes for the list of error codes.
 */
typedef void (*mxc_uart_complete_cb_t)(mxc_uart_req_t *req, int result);

/**
 * @brief   The callback routine used to indicate the transaction has terminated.
 *
 * @param   req          The details of the transaction.
 * @param   num          The number of characters actually copied
 * @param   result       See \ref MXC_Error_Codes for the list of error codes.
 */
typedef void (*mxc_uart_dma_complete_cb_t)(mxc_uart_req_t *req, int num, int result);

/**
 * @brief   The information required to perform a complete UART transaction
 *
 * @note    This structure is used by blocking, async, and DMA based transactions.
 * @note    "callback" only needs to be initialized for interrupt driven (Async) or DMA transactions.
 */
struct _mxc_uart_req_t {
    mxc_uart_regs_t *uart; ///<Point to UART registers
    const uint8_t *txData; ///< Buffer containing transmit data. For character sizes
        ///< < 8 bits, pad the MSB of each byte with zeros. For
        ///< character sizes > 8 bits, use two bytes per character
        ///< and pad the MSB of the upper byte with zeros
    uint8_t *rxData; ///< Buffer to store received data For character sizes
        ///< < 8 bits, pad the MSB of each byte with zeros. For
        ///< character sizes > 8 bits, use two bytes per character
        ///< and pad the MSB of the upper byte with zeros
    uint32_t txLen; ///< Number of bytes to be sent from txData
    uint32_t rxLen; ///< Number of bytes to be stored in rxData
    volatile uint32_t txCnt; ///< Number of bytes actually transmitted from txData
    volatile uint32_t rxCnt; ///< Number of bytes stored in rxData

    mxc_uart_complete_cb_t callback; ///< Pointer to function called when transaction is complete
};

/***** Function Prototypes *****/

/* ************************************************************************* */
/* Control/Configuration functions                                           */
/* ************************************************************************* */

/**
 * @brief   Initialize and enable UART peripheral.
 * 
 * This function initializes everything necessary to call a UART transaction function.
 * Some parameters are set to defaults as follows:
 * UART Data Size    - 8 bits
 * UART Stop Bits    - 1 bit
 * UART Parity       - None
 * UART Flow Control - None
 * 
 * These parameters can be modified after initialization using low level functions
 * 
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 * @param   baud         The requested clock frequency. The actual clock frequency
 *                       will be returned by the function if successful.
 * @param   clock        Clock source
 *
 * @return  Success/Fail, see \ref MXC_Error_Codes for a list of return codes.
 */
int MXC_UART_Init(mxc_uart_regs_t *uart, unsigned int baud, mxc_uart_clock_t clock);

/**
 * @brief   Disable and shutdown UART peripheral.
 *
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 *
 * @return  Success/Fail, see \ref MXC_Error_Codes for a list of return codes.
 */
int MXC_UART_Shutdown(mxc_uart_regs_t *uart);

/**
 * @brief   Set the frequency of the UART interface.
 *
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 * @param   baud         The desired baud rate
 * @param   clock        Clock source
 *
 * @return  Negative if error, otherwise actual speed set. See \ref
 *          MXC_Error_Codes for the list of error return codes.
 */
int MXC_UART_SetFrequency(mxc_uart_regs_t *uart, unsigned int baud, mxc_uart_clock_t clock);

/**
 * @brief   Get the frequency of the UART interface.
 *
 * @note    This function is applicable in Master mode only
 *
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 *
 * @return  The UART baud rate
 */
int MXC_UART_GetFrequency(mxc_uart_regs_t *uart);

/**
 * @brief   Sets the number of bits per character
 * 
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 * @param   dataSize     The number of bits per character (5-8 bits/character are valid)
 *
 * @return  Success/Fail, see \ref MXC_Error_Codes for a list of return codes.
 */
int MXC_UART_SetDataSize(mxc_uart_regs_t *uart, int dataSize);

/**
 * @brief   Sets the number of stop bits sent at the end of a character
 * 
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 * @param   stopBits     The number of stop bits used
 *
 * @return  Success/Fail, see \ref MXC_Error_Codes for a list of return codes.
 */
int MXC_UART_SetStopBits(mxc_uart_regs_t *uart, mxc_uart_stop_t stopBits);

/**
 * @brief   Sets the type of parity generation used
 * 
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 * @param   parity       see \ref UART Parity Types for details
 *
 * @return  Success/Fail, see \ref MXC_Error_Codes for a list of return codes.
 */
int MXC_UART_SetParity(mxc_uart_regs_t *uart, mxc_uart_parity_t parity);

/* ************************************************************************* */
/* Low-level functions                                                       */
/* ************************************************************************* */

/**
 * @brief   Reads the next available character. If no character is available, this function
 *          will return an error.
 *
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 *
 * @return  The character read, otherwise see \ref MXC_Error_Codes for a list of return codes.
 */
int MXC_UART_ReadCharacterRaw(mxc_uart_regs_t *uart);

/**
 * @brief   Writes a character on the UART. If the character cannot be written because the
 *          transmit FIFO is currently full, this function returns an error.
 *
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 * @param   character         The character to write
 *
 * @return  Success/Fail, see \ref MXC_Error_Codes for a list of return codes.
 */
int MXC_UART_WriteCharacterRaw(mxc_uart_regs_t *uart, uint8_t character);

/**
 * @brief   Reads the next available character
 *
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 *
 * @return  The character read, otherwise see \ref MXC_Error_Codes for a list of return codes.
 */
int MXC_UART_ReadCharacter(mxc_uart_regs_t *uart);

/**
 * @brief   Writes a character on the UART
 *
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 * @param   character    The character to write 
 *
 * @return  Success/Fail, see \ref MXC_Error_Codes for a list of return codes.
 */
int MXC_UART_WriteCharacter(mxc_uart_regs_t *uart, uint8_t character);

/**
 * @brief   Get the number of bytes currently available in the receive FIFO.
 *
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 *
 * @return  The number of bytes available.
 */
unsigned int MXC_UART_GetRXFIFOAvailable(mxc_uart_regs_t *uart);

/**
 * @brief   Get the amount of free space available in the transmit FIFO.
 *
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 *
 * @return  The number of bytes available.
 */
unsigned int MXC_UART_GetTXFIFOAvailable(mxc_uart_regs_t *uart);

/**
 * @brief   Set the receive threshold level.
 * 
 * @note    RX FIFO Receive threshold. Smaller values will cause
 *          interrupts to occur more often, but reduce the possibility
 *          of losing data because of a FIFO overflow. Larger values
 *          will reduce the time required by the ISR, but increase the 
 *          possibility of data loss. Passing an invalid value will
 *          cause the driver to use the value already set in the 
 *          appropriate register.
 *
 * @param   uart         Pointer to UART registers (selects the UART block used.)
 * @param   numBytes     The threshold level to set. This value must be
 *                       between 0 and 8 inclusive.
 *
 * @return  Success/Fail, see \ref MXC_Error_Codes for a list of return codes.
 */
int MXC_UART_SetRXThreshold(mxc_uart_regs_t *uart, unsigned int numBytes);

/**@} end of group uart */

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX78000_UART_H_
