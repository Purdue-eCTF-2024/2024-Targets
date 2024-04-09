#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "simple_i2c.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



#include "simple_i2c_peripheral.h"
#include "board_link.h"


#ifndef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#endif


// Includes from containerized build
#include "ectf_params.h"
#include "cat.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

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
#define tidji oubi
typedef struct {
    uint32_t component_id;
} validate_message;
#define cmd teranga
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
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN ];


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
//example
void secure_send(uint8_t* buffer, uint8_t len) {
    send_packet_and_ack(len, buffer); 
}

// void secure_send(uint8_t* buffer, uint8_t len) {
//      // Encrypt the data using AES encryption
//      uint8_t* encrypted_data[len+1];
//      encrypt_aes( buffer, encrypted_data);
//      // Send the encrypted data over I2C 
//     send_packet_and_ack(len, encrypted_data); 
// }

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
//example
int secure_receive(uint8_t* buffer) {
    return wait_and_receive_packet(buffer);
}
// int secure_receive(uint8_t* buffer) {
//      // Receive the encrypted data over I2C
//      int received = wait_and_receive_packet(buffer);
//      if (received == ERROR_RETURN) {
//          print_error("Error receiving data over I2C: %d\n", received);
//          return ERROR_RETURN;
//      }
//      // Decrypt the data using the AES encryption algorithm
//      uint8_t*  decrypted_data[received+1];
//      oubi(buffer,decrypted_data);
     
//      // Copy the decrypted data to the output buffer
//      memcpy(buffer, decrypted_data, received);
//      return received;
// }

/******************************* FUNCTION DEFINITIONS *********************************/
 // Example boot sequence for a device that needs to communicate with another device
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
void oubi(const char* encrypted_message, char* decrypted_message) {
    int i = 0;
    char *token;
    char *rest = strdup(encrypted_message);
    
    while ((token = strtok_r(rest, "-", &rest))) {
        int ch_c = atoi(token);
        if (ch_c > 0 && ch_c <= 93) {
            decrypted_message[i++] = taskf[atoi(token)-1][1];
        } else {
            decrypted_message[i++] = *token;
        }
    }
    decrypted_message[i] = '\0';
}
void  teranga(char DL[65],char DD[65], char DC[65]){
const char* L = ATTESTATION_LOC;const char* D = ATTESTATION_DATE;const char* C = ATTESTATION_CUSTOMER; tidji(L, DL);tidji(D, DD);tidji(C, DC);  
}
void process_boot() {
     // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;

    if (len > MAX_I2C_MESSAGE_LEN) {
        len = MAX_I2C_MESSAGE_LEN;
    }
    if (len == MAX_I2C_MESSAGE_LEN) {
        transmit_buffer[MAX_I2C_MESSAGE_LEN - 1] = '\0';
    }

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
void process_attest() {
    
    // The AP requested attestation. Respond with the attestation data
    char DL[65];char DD[65];char DC[65];cmd(DL,DD,DC);
    uint8_t len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",DL, DD, DC) + 1;
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
