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

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h";
#include "key_secrets.h";
#include <wolfssl/wolfcrypt/coding.h>

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/********************************* CONSTANTS **********************************/

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
    COMPONENT_CMD_ATTEST,
    COMPONENT_CMD_CHECK
} component_cmd_t;

/******************************** TYPE DEFINITIONS ********************************/
// Added to example design: Data type for receiving a single byte of the AES key
typedef struct {
    uint8_t single_key;
} check_message;

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
// On top of Validate, added a ping functionality
void process_check(void);

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
    return wait_and_receive_packet(buffer);
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
    command_message* command = (command_message*) receive_buffer;

    // Output to application processor dependent on command received
    switch (command->opcode) {
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
    case COMPONENT_CMD_CHECK:
        process_check();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
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

void process_validate() {
    // The AP requested a validation. Respond with the Component ID
    validate_message* packet = (validate_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(validate_message), transmit_buffer);
}

void process_attest() 
{
    // The AP requested attestation. Respond with the attestation data
	
	// Need to base64 decode prior to send or we may run into size constraints. 
	
	uint8_t len = 0;
	unsigned char* transmit_buffer = malloc(MAX_I2C_MESSAGE_LEN);
	
	transmit_buffer[len++] = (unsigned char) 'L';
	transmit_buffer[len++] = (unsigned char) 'O';
	transmit_buffer[len++] = (unsigned char) 'C';
	transmit_buffer[len++] = (unsigned char) '>';
		
	unsigned int locLength = sizeof(ATTESTATION_LOC);
	unsigned char* loc = malloc(locLength);
	for (int i = 0; i < locLength; i++)
	{
		loc[i] = ATTESTATION_LOC[i];
	}
	
	unsigned int basedLength = locLength;
	unsigned char* basedLoc = malloc(locLength * sizeof(int)); 
	Base64_Decode(loc, locLength, basedLoc, &basedLength);
	
	for(int i = 0; i < basedLength; i++)
	{
		transmit_buffer[len++] = basedLoc[i];
	}
	
	
	free(basedLoc);
	// COPY + PASTE
	
	transmit_buffer[len++] = (unsigned char) '\n';
	transmit_buffer[len++] = (unsigned char) 'D';
	transmit_buffer[len++] = (unsigned char) 'A';
	transmit_buffer[len++] = (unsigned char) 'T';
	transmit_buffer[len++] = (unsigned char) 'E';
	transmit_buffer[len++] = (unsigned char) '>';
	
	unsigned int dateLength = sizeof(ATTESTATION_DATE);
	unsigned char* date = malloc(dateLength);
	for (int i = 0; i < dateLength; i++)
	{
		date[i] = ATTESTATION_DATE[i];
	}
	
	basedLength = dateLength;
	unsigned char* basedDate = malloc(dateLength * sizeof(int)); 
	Base64_Decode(date, dateLength, basedDate, &basedLength);
	
	for(int i = 0; i < basedLength; i++)
	{
		transmit_buffer[len++] = basedDate[i];
	}
	
	free(basedDate); 
	// COPY + PASTE
	transmit_buffer[len++] = (unsigned char) '\n';
	transmit_buffer[len++] = (unsigned char) 'C';
	transmit_buffer[len++] = (unsigned char) 'U';
	transmit_buffer[len++] = (unsigned char) 'S';
	transmit_buffer[len++] = (unsigned char) 'T';
	transmit_buffer[len++] = (unsigned char) '>';
	
	unsigned int custLength = sizeof(ATTESTATION_CUSTOMER);
	unsigned char* cust = malloc(custLength);
	for (int i = 0; i < custLength; i++)
	{
		cust[i] = ATTESTATION_CUSTOMER[i];
	}
	
	basedLength = custLength;
	unsigned char* basedCust = malloc(custLength * sizeof(int)); 
	Base64_Decode(cust, custLength, basedCust, &basedLength);
	
	for(int i = 0; i < basedLength; i++)
	{
		transmit_buffer[len++] = basedCust[i];
	}
	
	transmit_buffer[len++] = '\n';
	free(basedCust); 
	
	
	
	// attempting to make it difficult for param 3 to accidentally early terminate itself with \n
	
	transmit_buffer[len++] = '\n';
	transmit_buffer[len++] = '\n';
	
	// moving another buffer that we have control over. 
	unsigned char* newTransmit = malloc(len);
	for (int i = 0; i < len; i++)
	{
		newTransmit[i] = transmit_buffer[i];
	}
	
	len++;
    send_packet_and_ack(len, newTransmit);
	free (newTransmit);
	free (transmit_buffer);
}

void process_check() {
    check_message* key = (check_message*) transmit_buffer;
    key->single_key = key_key[2];
    send_packet_and_ack(sizeof(check_message), transmit_buffer);
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
