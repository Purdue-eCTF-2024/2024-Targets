/**
 * @file encrypted.c
 * @author Plaid Parliament of Pwning
 * @brief Contains boot code that is encrypted at load time
 * 
 * All the code in here is encrypted at load time and must be decrypted by the AP after verifiying all its components.
 * 
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include "encrypted.h"
#include "host_messaging.h"
#include "ap_secure_comm.h"

#include "mxc_delay.h"
#include "led.h"
#include "util.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

void post_boot_code_noop(void) {
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);

    MXC_Delay(200000);

    // Very simple LED-blinky code for distinguishing AP vs component
    // AP blinks LED1 (Red)
    while (1) {
        for (int i = 0; i < 100; i+=(i > 70 ? 1 : 2)) {
            LED_On(LED1);
            MXC_Delay(i * 80);
            LED_Off(LED1);
            MXC_Delay(8000 - (i * 80));
        }
        for (int i = 100; i > 0; i-=(i > 70 ? 1 : 2)) {
            LED_On(LED1);
            MXC_Delay(i * 80);
            LED_Off(LED1);
            MXC_Delay(8000 - (i * 80));
        }
        MXC_Delay(50000);
    }
}

/**
 * @brief Function that does the work after boot up
 * 
 * These functions are all decrypted at runtime once the components have been verified.
 */
void boot(void) {
    #if POST_BOOT_ENABLED
        POST_BOOT;
    #else
        post_boot_code_noop();
    #endif

    // HCF: post-boot code should never be able to terminate
    HALT_AND_CATCH_FIRE();
}
