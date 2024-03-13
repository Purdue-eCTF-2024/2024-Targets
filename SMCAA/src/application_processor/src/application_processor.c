/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2024 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
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
#include <stdlib.h>
#include <string.h>

#include "board_link.h"
#include "crypto.h"
#include "host_messaging.h"
#include "simple_flash.h"

#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define AP_PIN "123456"
#define AP_TOKEN "0123456789abcdef"
#define COMPONENT_IDS 0x11111124, 0x11111125
#define COMPONENT_CNT 2
#define AP_BOOT_MSG "Test boot message"
*/

// Flash Macros
#define FLASH_ADDR                                                             \
    ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

/******************************** TYPE DEFINITIONS
 * ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. This is not utilized by the example
// design but can be utilized by your design.
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN - 1];
} command_message;

// Data type for receiving a validate message
typedef struct {
    uint32_t component_id;
} validate_message;

// Data type for receiving a scan message
typedef struct {
    uint32_t component_id;
} scan_message;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint32_t component_cnt;
    uint32_t component_ids[32];
} flash_entry;

// Datatype for commands sent to components
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/********************************* GLOBAL VARIABLES
 * **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;

/******************************* POST BOOT FUNCTIONALITY
 * *********************************/
/**
 * @brief Secure Send
 *
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent
 *
 * Securely send data over I2C. This function is utilized in POST_BOOT
 functionality.
 * This function must be implemented by your team to align with the security
 requirements.

*/
int secure_send(uint8_t address, uint8_t *buffer, uint8_t len) {
    // size of secure message (md5 digest size + data size)
    int size_m = 16 + len;

    // allocate space for secure message
    uint8_t *msg = malloc(size_m);

    // create signature and place at start of msg
    create_signature(buffer, len, SECRET, msg);

    // copy data to msg behind the signature
    memcpy(msg + 16, buffer, len);

    // send packet and return the result
    return send_packet(address, size_m, msg);
}

/**
 * @brief Secure Receive
 *
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 *
 * @return int: number of bytes received, negative if error
 *
 * Securely receive data over I2C. This function is utilized in POST_BOOT
 * functionality. This function must be implemented by your team to align with
 * the security requirements.
 */
int secure_receive(i2c_addr_t address, uint8_t *buffer) {
    // buffer to hold recieved secure message
    uint8_t recieved[MAX_I2C_MESSAGE_LEN];

    // await to recieved message and its length
    int size_r = poll_and_receive_packet(address, recieved);

    // poll_and_receive_packet returns error or the message is too small
    if (size_r < 16)
        return ERROR_RETURN;

    // pointer offsets
    uint8_t *sig = recieved;
    uint8_t *data = recieved + 16;

    // calculate size of data (recieved size - md5 digest size)
    int size_d = size_r - 16;

    // return error if signature is does not match
    if (verify_signature(data, size_d, SECRET, sig))
        return ERROR_RETURN;

    // copy the data into message buffer
    memcpy(buffer, data, size_d);

    // return size of data
    return size_d;
}

/**
 * @brief Get Provisioned IDs
 *
 * @param uint32_t* buffer
 *
 * @return int: number of ids
 *
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT
 * functionality. This function must be implemented by your team.
 */
int get_provisioned_ids(uint32_t *buffer) {
    memcpy(buffer, flash_status.component_ids,
           flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

/********************************* UTILITIES **********************************/

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() {
    // Enable global interrupts
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t *)&flash_status,
                      sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids,
               COMPONENT_CNT * sizeof(uint32_t));

        flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status,
                           sizeof(flash_entry));
    }

    // Initialize board link interface
    board_link_init();
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr, uint8_t *transmit, uint8_t *receive) {
    // Send message
    int result = send_packet(addr, sizeof(uint8_t), transmit);
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    // Receive message
    int len = poll_and_receive_packet(addr, receive);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    return len;
}

int send_validate(i2c_addr_t addr) {
    // Allocate space for message (1 byte command + 16 byte nonce)
    // and recieved message (16 byte challenge)
    uint8_t transmit_buf[17];
    uint8_t recieve_buf[16];

    // Create command message
    transmit_buf[0] = COMPONENT_CMD_VALIDATE;

    // Create 16 byte nonce and the ptr to it
    uint8_t *nonce = transmit_buf + 1;
    trng(nonce, 16);

    // Send out command
    int len = send_packet(addr, 17, transmit_buf);
    if (len == ERROR_RETURN)
        return ERROR_RETURN;

    // Recieve challenge
    len = poll_and_receive_packet(addr, recieve_buf);
    if (len != 16)
        return ERROR_RETURN;

    // Check that the challenge is correct
    if (verify_signature(nonce, 16, SECRET, recieve_buf)) {
        print_error("Challenge mismatch\n");
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}

// Allows the AP to validate itself with a component
int recieve_validate(i2c_addr_t addr) {
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];

    // Recieve nonce
    int r = poll_and_receive_packet(addr, receive_buffer);
    if (r == ERROR_RETURN)
        return ERROR_RETURN;

    // Create sig (challenge) from recieved 16 byte nonce
    create_signature(receive_buffer, 16, SECRET, transmit_buffer);

    // Send sig back to component
    send_packet(addr, 16, transmit_buffer);

    // Recieve result
    r = poll_and_receive_packet(addr, receive_buffer);
    if (r == ERROR_RETURN)
        return ERROR_RETURN;

    // Check to see if the validate succeeded (0x01 = fail)
    if (*receive_buffer)
        return ERROR_RETURN;

    return SUCCESS_RETURN;
}

/******************************** COMPONENT COMMS
 * ********************************/

int scan_components() {
    // Print out provisioned component IDs
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        print_info("P>0x%08x\n", flash_status.component_ids[i]);
    }

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Scan scan command to each component
    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // I2C Blacklist:
        // 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }

        // Create command message
        command_message *command = (command_message *)transmit_buffer;
        command->opcode = COMPONENT_CMD_SCAN;

        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);

        // Success, device is present
        if (len > 0) {
            scan_message *scan = (scan_message *)receive_buffer;
            print_info("F>0x%08x\n", scan->component_id);
        }
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

int validate_components() {
    // Veryify each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr =
            component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Verify component
        if (send_validate(addr) == ERROR_RETURN) {
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }
    }
    return SUCCESS_RETURN;
}

int boot_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr =
            component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create boot message
        transmit_buffer[0] = COMPONENT_CMD_BOOT;
        send_packet(addr, 1, transmit_buffer);

        // AP verify flow
        if (recieve_validate(addr) == ERROR_RETURN) {
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        // If component has verifed AP, recieve component boot message
        poll_and_receive_packet(addr, receive_buffer);

        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i],
                   receive_buffer);
    }
    return SUCCESS_RETURN;
}

int attest_component(uint32_t component_id) {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // First validate component to ensure authenticity
    if (send_validate(addr) == ERROR_RETURN) {
        print_error("Could not validate component\n");
        return ERROR_RETURN;
    }

    // Create attestaion message
    transmit_buffer[0] = COMPONENT_CMD_ATTEST;
    send_packet(addr, 1, transmit_buffer);

    // Recieve validate message to prove AP is authentic
    if (recieve_validate(addr) == ERROR_RETURN) {
        print_error("Could not attest component\n");
        return ERROR_RETURN;
    }

    // Recieve attestation data
    poll_and_receive_packet(addr, receive_buffer);

    // Print out attestation data
    print_info("C>0x%08x\n", component_id);
    print_info("%s", receive_buffer);
    return SUCCESS_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
    print_success("Boot");

// POST BOOT FUNCTIONALITY
// DO NOT REMOVE IN YOUR DESIGN
#ifdef POST_BOOT
    POST_BOOT
#else
    // Everything after this point is modifiable in your design
    // LED flash to show that boot occurred
    for (int i = 0; i < 10; i++) {
        LED_On(LED1);
        MXC_Delay(50000);
        LED_On(LED2);
        MXC_Delay(50000);
        LED_On(LED3);
        MXC_Delay(50000);
        LED_Off(LED1);
        MXC_Delay(50000);
        LED_Off(LED2);
        MXC_Delay(50000);
        LED_Off(LED3);
        MXC_Delay(50000);
    }

    print_info("Application Processor Started\n");
#endif
}

// Compare the entered PIN to the correct PIN
int validate_pin() {
    char buf[7];
    recv_input("Enter pin: ", buf, 7);
    if (!strcmp(buf, AP_PIN)) {
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() {
    char buf[17];
    recv_input("Enter token: ", buf, 17);
    if (!strcmp(buf, AP_TOKEN)) {
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    if (validate_components() == ERROR_RETURN) {
        print_error("Components could not be validated\n");
        return;
    }
    print_debug("All Components validated\n");
    if (boot_components() == ERROR_RETURN) {
        print_error("Failed to boot all components\n");
        return;
    }
    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    // print_success("Boot\n");
    // Boot
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace() {
    char buf[11];

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf, 11);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf, 11);
    sscanf(buf, "%x", &component_id_out);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status,
                               sizeof(flash_entry));

            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
                        component_id_in);
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",
                component_id_out);
}

// Attest a component if the PIN is correct
void attempt_attest() {
    char buf[11];

    if (validate_pin()) {
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", buf, 11);
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

/*********************************** MAIN *************************************/

int main() {
    // Initialize board
    init();

    // Print the component IDs to be helpful
    // Your design does not need to do this
    print_info("Application Processor Started\n");

    // Handle commands forever
    char buf[9];
    while (1) {
        recv_input("Enter Command: ", buf, 9);

        // Strip newline
        buf[strcspn(buf, "\n")] = '\0';

        // Execute requested command
        if (!strcmp(buf, "list")) {
            scan_components();
        } else if (!strcmp(buf, "boot")) {
            attempt_boot();
        } else if (!strcmp(buf, "replace")) {
            attempt_replace();
        } else if (!strcmp(buf, "attest")) {
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}
