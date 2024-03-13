/**
 * @file component.c
 * @author Jacob Doll 
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Include Custom TTU security headers */ 
#include "simple_crypto.h"
#include "security.h"
/* ################################### */

#include "simple_i2c_peripheral.h"
#include "board_link.h"

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/********************************* CONSTANTS **********************************/

#define PEPPER_LEN strlen(HASH_PEPPER)

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define COMPONENT_ID 0x11111124
#define COMPONENT_BOOT_MSG "Component boot"
#define ATTESTATION_LOC "McLean"
#define ATTESTATION_DATE "08/08/08"
#define ATTESTATION_CUSTOMER "Fritz"
*/

/******************************** TYPE DEFINITIONS ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for receiving messages from the AP
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

typedef struct {
    uint32_t component_id;
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
void secure_send(uint8_t* buffer, uint8_t len) {

    size_t encrypted_len = len + 1 + IV_SIZE + TAG_SIZE;
    uint8_t encrypted_packet[encrypted_len];

    if (create_encrypted_packet(buffer, len, ENCRYPTION_KEY, encrypted_packet) != 0) {
        printf("Error: Failed to encrypt packet\n");
        return;
    }

    send_packet_and_ack(encrypted_len, encrypted_packet);
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(uint8_t* buffer) {
    wait_and_receive_packet(buffer);

    size_t decrypted_len = buffer[0] - 1 - IV_SIZE - TAG_SIZE;
    uint8_t decrypted_packet[decrypted_len];

    if (decrypt_encrypted_packet(buffer, ENCRYPTION_KEY, decrypted_packet) != 0) {
        printf("Error: Failed to decrypt packet\n");
        return -1;
    }

    memcpy(buffer, decrypted_packet, decrypted_len);
    return decrypted_len;
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
}

// Handle a transaction from the AP
void component_process_cmd() {

    uint8_t opcode = receive_buffer[0];
    char *received_ap_token = receive_buffer + 1;

    if (!constant_strcmp(received_ap_token, AP_FIRMWARE_TOKEN)) {
        printf("Error: Could not authenticate AP\n");
        return;
    }

    // Output to application processor dependent on command received
    switch (opcode) {
    case COMPONENT_CMD_BOOT:
        process_boot();
        break;
    case COMPONENT_CMD_SCAN:
        process_scan();
        break;
    case COMPONENT_CMD_VALIDATE:
        process_validate();
        break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", opcode);
        break;
    }
}

void process_boot() {
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message

    // char component_hash[10 + PEPPER_LEN]; // Component ID + Pepper
    // uint8_t component_id_hex[10]; // Component ID in hex
    // sprintf(component_id_hex, "0x%08x", COMPONENT_ID); // Convert component ID to hex (0x... format)
    // memcpy(component_hash, component_id_hex, 10); // Copy component ID to hash
    // memcpy(component_hash + 10, HASH_PEPPER, PEPPER_LEN); // Copy pepper to hash
    // uint8_t hash_out[HASH_SIZE]; // Output hash
    // sha256_hash(component_hash, 10 + PEPPER_LEN, hash_out); // Hash the component ID and pepper

    // TODO: Figure out how to send the hash_str to the AP

    // Create a buffer to attach the COMPONENT_FIRMWARE_TOKEN and COMPONENT_BOOT_MSG
    uint8_t len = strlen(COMPONENT_FIRMWARE_TOKEN) + strlen(COMPONENT_BOOT_MSG) + 2;
    uint8_t buffer[len];

    // Copy the COMPONENT_FIRMWARE_TOKEN and COMPONENT_BOOT_MSG into the buffer
    strcpy((char *)buffer, COMPONENT_FIRMWARE_TOKEN);
    strcpy((char *)buffer + strlen(COMPONENT_FIRMWARE_TOKEN) + 1, COMPONENT_BOOT_MSG);


    // uint8_t len = HASH_SIZE + strlen(COMPONENT_BOOT_MSG) + 1;
    // uint8_t buffer[len];

    // memcpy(buffer, hash_out, HASH_SIZE); // Copy hash
    // strcpy(buffer + HASH_SIZE, COMPONENT_BOOT_MSG); // Copy boot message

    // Null terminate the buffer
    // buffer[len-1] = '\0';

    send_packet_and_ack(len, buffer);


    // uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    // memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
    // send_packet_and_ack(len, transmit_buffer);
    // Call the boot function
    boot();
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
}

void process_validate() {
    // The AP requested a validation. Respond with the Component ID
    validate_message* packet = (validate_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(validate_message), transmit_buffer);
}

void process_attest() {
    // The AP requested attestation. Respond with the attestation data
    uint8_t len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;
    send_packet_and_ack(len, transmit_buffer);
}

/*********************************** MAIN *************************************/

int main(void) {
    printf("Component Started\n");
    
    // Enable Global Interrupts
    __enable_irq();
    
    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);
    
    LED_On(LED2);

    while (1) {
        wait_and_receive_packet(receive_buffer);
        component_process_cmd();
    }
}
