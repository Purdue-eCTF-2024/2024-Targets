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
#include "simple_crypto.h"

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
//Added COMPONENT_SET_KEY to set encryption in components and
//COMPONENT_MSG_ENC so that secure_receive knows to decrypt the message
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST,
	COMPONENT_SET_KEY,
    COMPONENT_MSG_ENC = 0xFF
} component_cmd_t;

/******************************** TYPE DEFINITIONS ********************************/
//In order to secure the existing protocol, these macros will be used in secure send/receive to 
//reformat the message before encryption and after decryption

#define PROTOCOL_OFFSET		3	//Move data 2 bytes
#define CHECKSUM_BYTES		2	//2 checksum bytes
#define PROROCOL_LEN_ADD	PROTOCOL_OFFSET + CHECKSUM_BYTES


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

void ReceiveKey();																//Receive encryption key
void CRC16(uint8_t* buffer,int length, uint8_t* pnSumLow, uint8_t* pnSumHigh);	//Checksum for encrypted messages

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

uint8_t 	g_nSequenceNumber;											//Sequence number to sync with AP
bool 		g_bMessageWasEncrypted;										//So I know message was received as encrypted and is valid
uint8_t 	g_nKey[KEY_SIZE];											//Encryption key
const char* g_pszKeyRecievedMessage = "Key Received";					//Message to verify I have the key

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
void secure_send(uint8_t* buffer, uint8_t len) 
{
	uint8_t nSumLow, nSumHigh;
	uint8_t temp_buffer[MAX_I2C_MESSAGE_LEN];
  
	//First I need to reformat the message by shifting the current data to a higher index
    for(int i = len - 1; i >= 0; i--)
        buffer[i+PROTOCOL_OFFSET] = buffer[i];    
    len+=PROROCOL_LEN_ADD;												//Add room for length byte, seq number, and checksum
	len += BLOCK_SIZE - ((len - 2) % BLOCK_SIZE);						//Add bytes to make length multiple of BLOCK_SIZE
																		//First 2 bytes are not encrypted.
	//Now add encryption byte, length and seq number
    buffer[0] = COMPONENT_MSG_ENC;
    buffer[1] = len;
    buffer[2] = g_nSequenceNumber++;
	
	//Calculate checksum and add to message
	CRC16(buffer,len - 2, &nSumLow, &nSumHigh);
    buffer[len-2]=nSumLow;
    buffer[len-1]=nSumHigh;

	//Encrypt and send
	memcpy(temp_buffer,buffer,len);
	encrypt_sym(&temp_buffer[2], len-2, g_nKey, &buffer[2]); 
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
int secure_receive(uint8_t* buffer) 
{
	uint8_t nSumLow, nSumHigh;
    int len = wait_and_receive_packet(buffer);
	g_bMessageWasEncrypted = false;

	if(len>0)
    {
        if(buffer[0] == COMPONENT_MSG_ENC)								//Is message encrypted?
		{
			uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];

			decrypt_sym(&buffer[2], len - 2, g_nKey, receive_buffer);	//Decrypt

			memcpy(&buffer[2],receive_buffer,len - 2);
			CRC16(buffer,len - 2, &nSumLow, &nSumHigh);					//Calculate checksum

			//Validate checksum and then reformat message
			if(nSumLow == buffer[len -2] && nSumHigh == buffer[len - 1] && g_nSequenceNumber == buffer[2])
			{
				for(int i = PROTOCOL_OFFSET; i < len; i++)
		        	buffer[i - PROTOCOL_OFFSET] = buffer[i];    
		    	len-=PROROCOL_LEN_ADD;									//decrease length for length byte, seq number, and checksum  

		    	g_bMessageWasEncrypted = true;							//Set flag
			}
		}
    }
    return len;
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
    
    // LED loop to show that boot occurred
    while (1) 
	{
		secure_receive(receive_buffer);

		command_message* command = (command_message*) receive_buffer;

        switch (command->opcode) 
		{
			case COMPONENT_CMD_ATTEST:
				process_attest();
				break;
			default:
				printf("Error: Unrecognized command received %d\n", command->opcode);
				break;
    	}


        /*
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
		*/
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
	case COMPONENT_SET_KEY:
		ReceiveKey();
		break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
}

void process_boot() 
{
	if(g_bMessageWasEncrypted)											//If not valid encrypted message, do not boot
	{
		// The AP requested a boot. Set `component_boot` for the main loop and
		// respond with the boot message
		uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
		memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
		//send_packet_and_ack(len, transmit_buffer);
		secure_send(transmit_buffer, len);
		// Call the boot function
		boot();
	}
	else
	{
		int len = sprintf((char*)transmit_buffer, "Invalid Request!!") + 1;
		send_packet_and_ack(len, transmit_buffer);
	}
}

//Unchanged
void process_scan() 
{
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
}

void process_validate() 
{
	if(g_bMessageWasEncrypted)											//If not valid encrypted message, do not send data
	{
		// The AP requested a validation. Respond with the Component ID
		validate_message* packet = (validate_message*) transmit_buffer;
		packet->component_id = COMPONENT_ID;
		//send_packet_and_ack(sizeof(validate_message), transmit_buffer);
		secure_send(transmit_buffer, sizeof(validate_message));
	}
	else
	{
		int len = sprintf((char*)transmit_buffer, "Invalid Request!!") + 1;
		send_packet_and_ack(len, transmit_buffer);
	}
	
}

void process_attest() 
{
	uint8_t len;

	if(g_bMessageWasEncrypted)											//If not valid encrypted message, do not send data
	{
		// The AP requested attestation. Respond with the attestation data
		len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
		            ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;
		secure_send(transmit_buffer, len);
	}
	else
	{
		len = sprintf((char*)transmit_buffer, "Invalid Request!!") + 1;
		send_packet_and_ack(len, transmit_buffer);
	}
	
    
}

//Receive encryption key, load it, and reply
void ReceiveKey() 
{
	g_nSequenceNumber = component_id_to_i2c_addr(COMPONENT_ID);;
	decrypt_sym(&receive_buffer[1], KEY_SIZE, (uint8_t*)secret, g_nKey);

	int len = sprintf((char*)transmit_buffer, g_pszKeyRecievedMessage) + 1;
    secure_send(transmit_buffer, len);
}

void CRC16(uint8_t* buffer,int length, uint8_t* pnSumLow, uint8_t* pnSumHigh)
{
    uint16_t wSum=0xFFFF; 
    uint8_t k;
    for(int i=0;i<length;i++)
    {
        wSum ^= buffer[i] << 8;
        for( k = 0; k < 8; ++k ) 
        {
            if( wSum & 0x8000 )
                wSum = (wSum << 1) ^ 0x1021;
            else
                wSum = wSum << 1;
        }
    }
    *pnSumLow = wSum & 0xFF;
    *pnSumHigh = (wSum >> 8) & 0xFF;
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
        //wait_and_receive_packet(receive_buffer);
        secure_receive(receive_buffer);

        

        component_process_cmd();
    }
}
