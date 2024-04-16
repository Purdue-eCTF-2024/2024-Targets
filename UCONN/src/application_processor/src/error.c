/**
 * @file "error.h"
 * @author Kevin Marquis
 * @brief Error Handling Tools Implementation
 * @date 2024
 */

#include "error.h"
#include "board.h"
#include "led.h"
#include "mxc_delay.h"

/** @brief Flashes red error indicator lights.
 *
 * @return None.
 *
 */
void led_error(){
    LED_On(LED1);
    MXC_Delay(500000);
    LED_Off(LED1);
    MXC_Delay(500000);
}