/**
 * @file    tmr.h
 * @brief   Timer (TMR) function prototypes and data types.
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
#ifndef LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX78000_TMR_H_
#define LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX78000_TMR_H_

/* **** Includes **** */
#include <stdint.h>
#include <stdbool.h>
#include "mxc_device.h"
#include "tmr_regs.h"
#include "mxc_sys.h"
#include "gcr_regs.h"
#include "mcr_regs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup tmr Timer (TMR)
 * @ingroup periphlibs
 * @{
 */

/**
 * @brief Timer prescaler values
 */
typedef enum {
    TMR_PRES_1 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_1, /**< Divide input clock by 1 */
    TMR_PRES_2 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_2, /**< Divide input clock by 2 */
    TMR_PRES_4 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_4, /**< Divide input clock by 4 */
    TMR_PRES_8 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_8, /**< Divide input clock by 8 */
    TMR_PRES_16 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_16, /**< Divide input clock by 16 */
    TMR_PRES_32 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_32, /**< Divide input clock by 32 */
    TMR_PRES_64 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_64, /**< Divide input clock by 64 */
    TMR_PRES_128 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_128, /**< Divide input clock by 128 */
    TMR_PRES_256 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_256, /**< Divide input clock by 256 */
    TMR_PRES_512 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_512, /**< Divide input clock by 512 */
    TMR_PRES_1024 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_1024, /**< Divide input clock by 1024 */
    TMR_PRES_2048 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_2048, /**< Divide input clock by 2048 */
    TMR_PRES_4096 = MXC_S_TMR_CTRL0_CLKDIV_A_DIV_BY_4096 /**< Divide input clock by 4096 */
} mxc_tmr_pres_t;

/**
 * @brief Timer modes
 */
typedef enum {
    TMR_MODE_ONESHOT = MXC_S_TMR_CTRL0_MODE_A_ONE_SHOT, /**< Timer Mode ONESHOT */
    TMR_MODE_CONTINUOUS = MXC_S_TMR_CTRL0_MODE_A_CONTINUOUS, /**< Timer Mode CONTINUOUS */
    TMR_MODE_COUNTER = MXC_S_TMR_CTRL0_MODE_A_COUNTER, /**< Timer Mode COUNTER */
    TMR_MODE_PWM = MXC_S_TMR_CTRL0_MODE_A_PWM, /**< Timer Mode PWM */
    TMR_MODE_CAPTURE = MXC_S_TMR_CTRL0_MODE_A_CAPTURE, /**< Timer Mode CAPTURE */
    TMR_MODE_COMPARE = MXC_S_TMR_CTRL0_MODE_A_COMPARE, /**< Timer Mode COMPARE */
    TMR_MODE_GATED = MXC_S_TMR_CTRL0_MODE_A_GATED, /**< Timer Mode GATED */
    TMR_MODE_CAPTURE_COMPARE = MXC_S_TMR_CTRL0_MODE_A_CAPCOMP /**< Timer Mode CAPTURECOMPARE */
} mxc_tmr_mode_t;

/**
 * @brief Timer bit mode 
 * 
 */
typedef enum {
    TMR_BIT_MODE_32 = 0, /**< Timer Mode 32 bit  */
    TMR_BIT_MODE_16A, /**< Timer Mode Lower 16 bit */
    TMR_BIT_MODE_16B, /**< Timer Mode Upper 16 bit */
} mxc_tmr_bit_mode_t;

/**
 * @brief Timer units of time enumeration
 */
typedef enum {
    TMR_UNIT_NANOSEC = 0, /**< Nanosecond Unit Indicator */
    TMR_UNIT_MICROSEC, /**< Microsecond Unit Indicator */
    TMR_UNIT_MILLISEC, /**< Millisecond Unit Indicator */
    TMR_UNIT_SEC, /**< Second Unit Indicator */
} mxc_tmr_unit_t;

/**
 * @brief      Peripheral Clock settings 
 */
typedef enum {
    MXC_TMR_APB_CLK = 0,
    MXC_TMR_EXT_CLK,
    /*8M and 60M clocks can be used for Timers 0,1,2 and 3*/
    MXC_TMR_60M_CLK,
    MXC_TMR_8M_CLK,
    /*32K clock can be used for Timers 0,1,2,3 and 4*/
    MXC_TMR_32K_CLK,
    /*8K and EXT clocks can only be used for Timers 4 and 5*/
    MXC_TMR_8K_CLK,
    MXC_TMR_8M_DIV8_CLK
} mxc_tmr_clock_t;

/**
 * @brief Timer Configuration
 */
typedef struct {
    mxc_tmr_pres_t pres; /**< Desired timer prescaler */
    mxc_tmr_mode_t mode; /**< Desired timer mode */
    mxc_tmr_bit_mode_t bitMode; /**< Desired timer bits */
    mxc_tmr_clock_t clock; /**< Desired clock source */
    uint32_t cmp_cnt; /**< Compare register value in timer ticks */
    unsigned pol; /**< Polarity (0 or 1) */
} mxc_tmr_cfg_t;

/* **** Definitions **** */
typedef void (*mxc_tmr_complete_t)(int error);

/* **** Function Prototypes **** */

/**
 * @brief   Initialize timer module clock.
 * @param   tmr        Pointer to timer module to initialize.
 * @param   cfg        System configuration object
 * @param   init_pins  True will initialize pins corresponding to the TMR and False will not if pins are pinned out otherwise it will not
 *                     be used
 * 
 * @return  Success/Fail, see \ref MXC_Error_Codes for a list of return codes.
 */
int MXC_TMR_Init(mxc_tmr_regs_t *tmr, mxc_tmr_cfg_t *cfg, bool init_pins);

/**
 * @brief   Shutdown timer module clock.
 * @param   tmr  Pointer to timer module to initialize.
 */
void MXC_TMR_Shutdown(mxc_tmr_regs_t *tmr);

/**
 * @brief   Start the timer counting.
 * @param   tmr  Pointer to timer module to initialize.
 */
void MXC_TMR_Start(mxc_tmr_regs_t *tmr);

/**@} end of group tmr */

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX78000_TMR_H_