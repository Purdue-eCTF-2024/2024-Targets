/**
 * @file
 * @brief    Asynchronous delay routines based on the SysTick Timer.
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
#ifndef LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX78000_MXC_DELAY_H_
#define LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX78000_MXC_DELAY_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup devicelibs
 * @defgroup    MXC_delay Delay Utility Functions
 * @brief       Asynchronous delay routines based on the SysTick Timer
 * @{
 */

/***** Definitions *****/
/**
 * Macro used to specify a microsecond timing parameter in seconds.
 * \code
 * x = SEC(3) // 3 seconds -> x = 3,000,000
 * \endcode
 */
#define MXC_DELAY_SEC(s) (((uint32_t)s) * 1000000UL)
/**
 * Macro used to specify a microsecond timing parameter in milliseconds.
 * \code
 * x = MSEC(3) // 3ms -> x = 3,000
 * \endcode
 */
#define MXC_DELAY_MSEC(ms) (ms * 1000UL)
/**
 * Macro used to specify a microsecond timing parameter.
 * \code
 * x = USEC(3) // 3us -> x = 3
 * \endcode
 */
#define MXC_DELAY_USEC(us) (us)

#ifdef __riscv

/**
 * @brief      Blocks and delays for the specified number of microseconds.
 * @details    Uses the Performance Counter to create the requested delay. The current
 *             and settings of the performance counter registers will be destroyed.
 * @param      us    microseconds to delay
 * @return     #E_NO_ERROR if no errors, @ref MXC_Error_Codes "error" if unsuccessful.
 */
int MXC_Delay(uint32_t us);

#else

int MXC_DelayTicks(uint32_t ticks);

/***** Function Prototypes *****/

/**
 * @brief      Blocks and delays for the specified number of microseconds.
 * @details    Uses the SysTick to create the requested delay. If the SysTick is
 *             running, the current settings will be used. If the SysTick is not
 *             running, it will be started.
 * @param      us    microseconds to delay
 * @return     #E_NO_ERROR if no errors, @ref MXC_Error_Codes "error" if unsuccessful.
 */
int MXC_Delay(uint32_t us);

/**@} end of group MXC_delay */

#endif /* __riscv */

#ifdef __cplusplus
}
#endif

#endif // LIBRARIES_PERIPHDRIVERS_INCLUDE_MAX78000_MXC_DELAY_H_