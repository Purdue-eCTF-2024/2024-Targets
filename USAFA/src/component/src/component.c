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

#include "simple_i2c_peripheral.h"
#include "board_link.h"
#include "simple_flash.h"

// #include "../../application_processor/inc/simple_crypto.h"
#include "simple_crypto.h"

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

#include "host_messaging.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif


/******************************** TYPE DEFINITIONS ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_VERIFICATION,
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
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
    uint32_t verification_key;
} verification_message;

typedef struct {
    uint32_t component_id;
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

typedef struct {
    uint32_t flash_magic;
    char attestation_loc[10];
    char attestation_date[10];
    char attestation_customer[10];
} flash_component;

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void process_key_sync(void);
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
flash_component flash_status;

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
    for (int i = 0; i < len; i++) {
        buffer[i] = buffer[i] ^ MESSAGE_KEY;
    }
// uint8_t newBuff[len];
// uint32_t tempArray [4] = {HASH_SECRET1, HASH_SECRET2, HASH_SECRET3, HASH_SECRET4};
// uint8_t* key_128;
// key_128 = (uint8_t*)tempArray;

// // encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) 
// encrypt_sym(buffer, len, key_128, newBuff);

send_packet_and_ack(len, buffer); 
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

// decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {

    uint8_t lengthReceived = wait_and_receive_packet(buffer);

    for (int i = 0; i < lengthReceived; i++) {
        buffer[i] = buffer[i] ^ MESSAGE_KEY;
    }

// uint8_t* outPut = buffer;
// uint32_t tempArray [4] = {HASH_SECRET1, HASH_SECRET2, HASH_SECRET3, HASH_SECRET4};
// uint8_t* key_128;
// key_128 = (uint8_t*)tempArray;

// decrypt_sym(outPut, lengthReceived, key_128, buffer);

return lengthReceived;
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
        wait_and_receive_packet(receive_buffer);
        component_process_cmd();

        // TEST for SR 5
        // char name[strlen("Junhyung Park")];
        
        // int size = secure_receive((uint8_t*)name);

        // print_info("secure receive: %i\n\r", size);

        // for (int i = 0; i < size; i++) {
        //     LED_On(LED1);
        //     MXC_Delay(500000);
        //     LED_Off(LED1);
        //     MXC_Delay(500000);
        // }

        // MXC_Delay(5000000);

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
    command_message* command = (command_message*) receive_buffer;

    // Output to application processor dependent on command received
    switch (command->opcode) {
    case COMPONENT_CMD_VERIFICATION:
        process_key_sync();
        break;
    case COMPONENT_CMD_BOOT:
        process_boot();
        break;
    case COMPONENT_CMD_SCAN:
        process_scan();
        break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
}

void process_key_sync() {
    verification_message* packet = (verification_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    packet->verification_key = verificationKey;
    send_packet_and_ack(sizeof(verification_message), transmit_buffer);
}

void process_boot() {
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
    send_packet_and_ack(len, transmit_buffer);
    // Call the boot function
    boot();
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
}

void process_attest() {
    // The AP requested attestation. Respond with the attestation data
    uint8_t len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;
    send_packet_and_ack(len, transmit_buffer);
}

void init() {
    
    // Enable global interrupts
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    //flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component Attestation data from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {

        flash_status.flash_magic = FLASH_MAGIC;
        strcpy(flash_status.attestation_loc, ATTESTATION_LOC);
        strcpy(flash_status.attestation_date, ATTESTATION_DATE);
        strcpy(flash_status.attestation_customer, ATTESTATION_CUSTOMER);

        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_status));
    }

    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);

}
/*********************************** MAIN *************************************/

int main(void) {
    printf("Component Started\n");
    
    // Initialize board
    init();
    
    LED_On(LED2);

    while (1) {
        wait_and_receive_packet(receive_buffer);

        component_process_cmd();
    }
}