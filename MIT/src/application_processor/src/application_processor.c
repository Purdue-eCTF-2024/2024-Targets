/**
 * @file application_processor.c
 * @author MIT TechSec
 * @brief eCTF AP Implementation
 * @date 2024
 */

#include "board.h"
#include "i2c.h"
#include "icc.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "board_link.h"
#include "simple_flash.h"
#include "host_messaging.h"

#ifdef POST_BOOT
#include "mxc_delay.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

// MIT: Includes for our custom features
#include "ap_common.h"

/********************************* UTILITIES **********************************/

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() {

    // Enable global interrupts    
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_first_boot();

    // MIT: Initialize our custom features
    common_init();
    // REDUNDANT
    session_init();
    session_init();
    session_init();
    
    // Initialize board link interface
    board_link_init_ap();
}

/*********************************** MAIN *************************************/

int main() {
    // Initialize board
    init();

    // Handle commands forever
    char * buf = get_uart_buf();
    while (1) {
        recv_input("Enter Command: ", 7);

        delay_rnd;

        // Execute requested command
        if (!strncmp(buf, "list", 4)) {
            scan_components();
        } else if (!strncmp(buf, "boot", 4)) {
            attempt_boot();
        } else if (!strncmp(buf, "replace", 7)) {
            attempt_replace();
        } else if (!strncmp(buf, "attest", 6)) {
            attempt_attest();
        } else {
            print_error("Unrecognized command\n");
        }
    }

    // Code never reaches here
    return 0;
}
