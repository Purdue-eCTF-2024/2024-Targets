/**
 * @file component.c
 * @author Kevin Marquis
 * @brief eCTF Component UConn Design Implementation
 * @date 2024
 *
 * @note Based on the example code provided in component.c by Jacob Doll. Copyright (c) 2024 The MITRE Corporation
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

//Cryptography Headers
#include "certs.h"

#include "handshake.h"
#include "wolfssl/wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/aes.h"

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
void process_handshake_demo();

/********************************* GLOBAL VARIABLES **********************************/
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
tls_key post_boot_io;
Aes post_boot_enc, post_boot_dec;
int msg_count = 0;

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
    uint8_t OUT_BUF[255] = {0};
    int full_len = len + sizeof(int);
    if (len < (255 - sizeof(int))){
        memcpy(OUT_BUF, &msg_count, sizeof(int));
        memcpy(OUT_BUF + sizeof(int), buffer, len);
    }
    else{
        return;
    }

    msg_count += 1;
    secure_send_lite(&post_boot_enc, &post_boot_io, OUT_BUF, full_len);
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
    int ret;
    uint8_t IN_BUF[255] = {0};
    ret = secure_receive_lite(&post_boot_dec, &post_boot_io, IN_BUF, 255);
    if (((int *)IN_BUF)[0] != msg_count){
        return -1;
    }
    ret -= sizeof(int);
    memcpy(buffer, IN_BUF + sizeof(int), ret);
    msg_count += 1;
    return ret;
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
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
}

void process_boot() {
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
    uint8_t transmit_buf[65] = {0};
    uint8_t iv[16] = {0};
    uint8_t ready_len = sprintf((char*)transmit_buffer, "Ready") + 1;
    send_packet_and_ack(ready_len, transmit_buffer);

    int ret = handshake_lite(&post_boot_io);
    if (ret != 0){
        print_error("Handshake failed.\n");
        return;
    }

    if (ret = wc_AesInit(&post_boot_enc, NULL, INVALID_DEVID) != 0) {
        // failed to initialize aes key
        print_error("Failed to initialize encryption key.\n");
        return;
    }
    if (ret = wc_AesSetKey(&post_boot_enc, post_boot_io.key, post_boot_io.key_len, iv, AES_ENCRYPTION) != 0) {
    // failed to set aes key
        print_error("Failed to initialize encryption key.\n");
        return;
    }

    for (int i = 0; i < 16; i++){
        iv[i] = 0;
    }

    if (ret = wc_AesInit(&post_boot_dec, NULL, INVALID_DEVID) != 0) {
        // failed to initialize aes key
        print_error("Failed to initialize decryption key.\n");
        return;
    }
    ret = wc_AesSetKey(&post_boot_dec, post_boot_io.key, post_boot_io.key_len, iv, AES_DECRYPTION);
    if (ret != 0) {
        print_error("Failed to initialize decryption key.\n");
        return;
    }

    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);

    secure_send_lite(&post_boot_enc, &post_boot_io, transmit_buffer, len);

    print_success("BOOTING!\n");

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
    int ret;
    tls_key validate_ctx;
    validate_message* packet = (validate_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(validate_message), transmit_buffer);
    ret = handshake_lite(&validate_ctx);
    if (ret != 0){
        print_error("Could not validate AP\n");
    }
}

void process_attest() {
    // The AP requested attestation. Respond with the attestation data
    uint8_t attest_data[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t iv[16] = {0};
    tls_key attest_ctx;
    int ret;
    Aes aes_ctx;
    uint8_t len = sprintf((char*)attest_data, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;
    uint8_t ready_len = sprintf((char*)transmit_buffer, "Ready") + 1;
    send_packet_and_ack(ready_len, transmit_buffer);
    
    ret = handshake_lite(&attest_ctx);
    if (ret != 0){
        print_error("Could not validate AP\n");
    }

    ret = wc_AesInit(&aes_ctx, NULL, INVALID_DEVID);
    if (ret != 0) {
        // failed to initialize aes key
        print_error("Failed to initialize encryption key.  Returned %d\n", ret);
    }

    ret = wc_AesSetKey(&aes_ctx, attest_ctx.key, attest_ctx.key_len, iv, AES_ENCRYPTION);
    if (ret != 0) {
        // failed to set aes key
        print_error("Failed to set encryption key.  Returned %d\n", ret);
    }

    ret = secure_send_lite(&aes_ctx, &attest_ctx, attest_data, len);
    if (ret != 0){
        print_error("Failed to send attestation data\n");
    }
}

/*********************************** MAIN *************************************/

int main(void) {
    int ret = MXC_TRNG_Init();
    if (ret){
        print_error("TRNG Failed to initialize!\n");
    }
    ret = MXC_AES_Init();
    if (ret != E_SUCCESS){
        print_error("Failed to turn on AES Unit\n");
    }
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
