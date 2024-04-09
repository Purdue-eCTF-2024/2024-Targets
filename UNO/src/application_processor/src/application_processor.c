/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
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
#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#endif

#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
#include <stdlib.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/coding.h>
#include "../../deployment/global_secrets.h"
#include "../../deployment/semiFun_secrets.h"
#include "../../deployment/key_secrets.h"

/********************************* CONSTANTS **********************************/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. 

// Added to example design: Data type for receiving a single byte of the AES key
typedef struct {
    uint8_t single_key;
} check_message;

typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
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
    COMPONENT_CMD_ATTEST,
    COMPONENT_CMD_CHECK
} component_cmd_t;

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.

*/
int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    return send_packet(address, len, buffer);
}

/**
 * @brief Secure Receive
 * 
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(i2c_addr_t address, uint8_t* buffer) {
    return poll_and_receive_packet(address, buffer);
}

/**
 * @brief Get Provisioned IDs
 * 
 * @param uint32_t* buffer
 * 
 * @return int: number of ids
 * 
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT functionality.
 * This function must be implemented by your team.
*/
int get_provisioned_ids(uint32_t* buffer) {
    memcpy(buffer, flash_status.component_ids, flash_status.component_cnt * sizeof(uint32_t));
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
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids, 
            COMPONENT_CNT*sizeof(uint32_t));

        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
    }
    
    // Initialize board link interface
    board_link_init();
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive) {
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

/******************************** COMPONENT COMMS ********************************/

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
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_SCAN;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);

        // Success, device is present
        if (len > 0) {
            scan_message* scan = (scan_message*) receive_buffer;
            print_info("F>0x%08x\n", scan->component_id);
        }
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

int validate_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send validate command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_VALIDATE;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }

        validate_message* validate = (validate_message*) receive_buffer;
        // Check that the result is correct
        if (validate->component_id != flash_status.component_ids[i]) {
            print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
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
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_BOOT;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i], receive_buffer);
    }
    return SUCCESS_RETURN;
}

int decrypt_attest(uint8_t* input, byte* decodeKey)
{
	// First step is to parse the main buffer for the encrypted string(s)
	
	int locIndex = 4; // stores position of encrypted beginning
	int ret;

	int locIndexEnd;
	for (locIndexEnd = locIndex + 1; locIndexEnd < MAX_I2C_MESSAGE_LEN; locIndexEnd++)
	{
		//print_info("HELPME- current val at %d = %02X", locIndexEnd, input[locIndexEnd]);
		if (input[locIndexEnd] == (unsigned char) '\n')
		{
			if (input[locIndexEnd + 1] == (unsigned char) 'D' && input[locIndexEnd + 2] == (unsigned char) 'A' && input[locIndexEnd + 3] == (unsigned char) 'T' && input[locIndexEnd + 4] == (unsigned char) 'E' && input[locIndexEnd + 5] == (unsigned char) '>')
			{
				break;
			}
		}
	}
	int locLength = locIndexEnd - locIndex;
	
	
	
	if (locLength % 16 != 0)
	{
		print_error("Error: BlockSize incorrect for param 1 -- current size = %d", locLength);
		return 62;
	}
	
	unsigned char* loc;
	loc = malloc(locLength);
	
	for (int i = 0; i < locLength; i++)
	{
		loc[i] = input[i+locIndex];
	}

	// Creating necessary variables for decryption
	Aes enc;

	
	// Initializing AES stuff
	ret = wc_AesInit(&enc, NULL, INVALID_DEVID);
    if (ret != 0) 
	{
        print_error("AesInit returned: %d", ret);
        return -1001;
    }
	
	//Setting the AES key using the user inputted PIN 
	ret = wc_AesSetKey(&enc, decodeKey, 32,  IV, AES_DECRYPTION);
	if (ret != 0) 
	{
        print_error("Failed to generate ACTUAL JAKE AES key. Error: %d", ret);
		return 103;
	}
	
	
	byte* output;
	output = malloc(locLength);
	 ret = wc_AesCbcDecrypt(&enc, output, loc, locLength);
	if (ret != 0)
	{
		print_error("Error: Unable to CBC Decrypt due to %d", ret);
		return 106;
	}
	
	// Counts pads
	int padCount = 0;
	for (int i = 0; i < locLength; i++)
	{
		if (output[i] == '!')
		{
			padCount++;
		}
	}
	
	// Inserts string into buffer excluding pads
	for (int i = 0; i < locLength - padCount; i++)
	{
		//print_info("Param 1 Output Byte[%d] = %02X", i, output[i]);
		if (output[i] > 127)
		{
			// THEN REPEAT FOR ALL 3 PARAMS
			print_error("Error: Param 1 contained an invalid utf-8 character. Did you use the correct pin?");
			return 69;
		}
		input[i+locIndex] = output[i];
	}
	
	int potDiff = padCount;
	// Corrects for the diffference in potential length difference after base64decode and the removal of padding
	for (int i = locIndexEnd - potDiff; i < MAX_I2C_MESSAGE_LEN; i++)
	{
		input[i] = input[i+potDiff];
	}
	
	for (int i = MAX_I2C_MESSAGE_LEN; i > MAX_I2C_MESSAGE_LEN - potDiff; i--)
	{
		input[i] = 0;
	}

	
	free(loc);
	free(output);

	
	/*
	/ Modularization sucks. Lets do it all in this single function :)
	/ Attempting to decrypt param 2
	/
	*/
	

	
	ret = wc_AesSetKey(&enc, decodeKey, 32,  IV, AES_DECRYPTION);
	if (ret != 0) 
	{
        print_error("Failed to generate ACTUAL JAKE AES key. Error: %d", ret);
		return 103;
	}
	
	locIndex = locIndexEnd - potDiff + 6; // stores position of encrypted beginning
	ret = 0;
	
	
	for (locIndexEnd = locIndex; locIndexEnd < MAX_I2C_MESSAGE_LEN; locIndexEnd++)
	{
		if (input[locIndexEnd] == (unsigned char) '\n')
		{
			if (input[locIndexEnd + 1] == (unsigned char) 'C' && input[locIndexEnd + 2] == (unsigned char) 'U' && input[locIndexEnd + 3] == (unsigned char) 'S' && input[locIndexEnd + 4] == (unsigned char) 'T' && input[locIndexEnd + 5] == (unsigned char) '>')
			{
				break;
			}
		}
		if (locIndexEnd - locIndex > 68)
		{
			print_error("unable to find attest date data");
			return 44; 
		}
	}
	
	
	locLength = locIndexEnd - locIndex;


	if (locLength % 16 != 0)
	{
		print_error("Error: BlockSize incorrect for param 2 -- length = %d (locEnd[%d] - loc[%d])", locLength, locIndexEnd, locIndex);
		return 62;
	}

	loc = malloc(locLength);
	
	for (int i = 0; i < locLength; i++)
	{
		loc[i] = input[i+locIndex];
	}
	
	output = malloc(locLength);
	 ret = wc_AesCbcDecrypt(&enc, output, loc, locLength);
	if (ret != 0)
	{
		print_error("Error: Unable to CBC Decrypt due to %d", ret);
		return 106;
	}

	// Counts pads
	padCount = 0;
	for (int i = 0; i < locLength; i++)
	{
		if (output[i] == '!')
		{
			padCount++;
		}
	}
	
	// Inserts string into buffer excluding pads
	for (int i = 0; i < locLength - padCount; i++)
	{
		//print_info("Output Byte[%d] = %02X", i, output[i]);
		if (output[i] > 127)
		{
			// THEN REPEAT FOR ALL 3 PARAMS
			print_error("Error: Param 1 contained an invalid utf-8 character. Did you use the correct pin?");
			return 69;
		}
		input[i+locIndex] = output[i];
	}
	
	potDiff = padCount;
	// Corrects for the diffference in potential length difference after base64decode and the removal of padding
	for (int i = locIndexEnd - potDiff; i < MAX_I2C_MESSAGE_LEN; i++)
	{
		input[i] = input[i+potDiff];
	}
	
	for (int i = MAX_I2C_MESSAGE_LEN; i > MAX_I2C_MESSAGE_LEN - potDiff; i--)
	{
		input[i] = 0;
	}

	
	free(loc);
	free(output);
	
	
	/*
	/ AHHAHAHAHAHA
	/ Attempting to decrypt param 3
	/
	*/
	
	
	ret = wc_AesSetKey(&enc, decodeKey, 32,  IV, AES_DECRYPTION);
	if (ret != 0) 
	{
        	print_error("Failed to generate ACTUAL JAKE AES key. Error: %d", ret);
		return 103;
	}
	
	locIndex = locIndexEnd - potDiff + 6; // stores position of encrypted beginning
	ret = 0;

	for (locIndexEnd = locIndex; locIndexEnd < MAX_I2C_MESSAGE_LEN; locIndexEnd++)
	{
		//print_info("HAHAHAHA- current val at %d = %02X", locIndexEnd, input[locIndexEnd]);
		if(input[locIndexEnd] == (unsigned char) '\n' && (locIndexEnd - locIndex) % 16 == 0)
		{
			if(input[locIndexEnd + 1] == (unsigned char) '\n'  && input[locIndexEnd + 2] == (unsigned char) '\n' )
			{
				break;
			}
		}
		if (locIndexEnd - locIndex > 68)
		{
			print_error("unable to find attest cust data");
			return 45; 
		}
	}
	
	locLength = locIndexEnd - locIndex;
	loc = malloc(locLength);
	
	for (int i = 0; i < locLength; i++)
	{
		loc[i] = input[i+locIndex];
	}
	
	if (locLength % 16 != 0)
	{
		print_error("Error: BlockSize incorrect for param 3 -- length = %d", locLength);
		return 62;
	}
	
	output = malloc(locLength);
	 ret = wc_AesCbcDecrypt(&enc, output, loc, locLength);
	if (ret != 0)
	{
		print_error("Error: Unable to CBC Decrypt due to %d", ret);
		return 106;
	}

	// Counts pads
	padCount = 0;
	for (int i = 0; i < locLength; i++)
	{
		if (output[i] == '!')
		{
			padCount++;
		}
	}
	
	// Inserts string into buffer excluding pads
	for (int i = 0; i < locLength - padCount; i++)
	{
		//print_info("Output Byte[%d] = %02X", i, output[i]);
		if (output[i] > 127)
		{
			// THEN REPEAT FOR ALL 3 PARAMS
			print_error("Error: Param 1 contained an invalid utf-8 character. Did you use the correct pin?");
			return 69;
		}
		input[i+locIndex] = output[i];
	}
	
	potDiff = padCount;
	// Corrects for the diffference in potential length difference after base64decode and the removal of padding
	for (int i = locIndexEnd - potDiff; i < MAX_I2C_MESSAGE_LEN; i++)
	{
		input[i] = input[i+potDiff];
	}
	
	for (int i = MAX_I2C_MESSAGE_LEN; i > MAX_I2C_MESSAGE_LEN - potDiff; i--)
	{
		input[i] = 0;
	}

	
	free(loc);
	free(output);
	
	
	return 0;
}



int decodePin(uint8_t* input, char* userPIN)
{
	int ret = 0;	
	int lengthKey = 32;
	byte* decodeKey = malloc(lengthKey);
	
	byte* tempBuf = malloc(lengthKey * sizeof(int));
	for (int i = 0; i < sizeof(AP_PIN); i++)
	{
		tempBuf[i] = (unsigned char) AP_PIN[i];
	}
		
	// Gotta remove the base 64 now
	unsigned int basedLength = lengthKey * sizeof(int);
	byte* basedOutput = malloc(basedLength);
	ret = Base64_Decode(tempBuf, sizeof(AP_PIN), basedOutput, &basedLength);
	free(tempBuf);
	if (ret != 0)
	{
		fprintf(stderr, "Error: Unable to BasedDecode  %d\n", ret);
		return 136;
	}
	if (basedLength != lengthKey)
	{
		print_error("Error: Decoded Key size incorrect");
		return 23;
	}	
	
	for (int i = 0; i < lengthKey; i++)
   {
	  decodeKey[i] = basedOutput[i] ^ (unsigned char) userPIN[i % 6];
   }
	
	ret = decrypt_attest(input, decodeKey);
	if (ret != 0)
	{
		print_error("Error: Unable to decypt data with given pin -- Decrypt returned %d", ret);
		return 54;
	}
	
	free(basedOutput);
	free(decodeKey); 
	return 0;
}


int attest_component(uint32_t component_id, char* userPIN) 
{
	MXC_Delay(500000);
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Create command message
    command_message* command = (command_message*) transmit_buffer;
    command->opcode = COMPONENT_CMD_ATTEST;

    // Send out command and receive result
    int len = issue_cmd(addr, transmit_buffer, receive_buffer);
    if (len == ERROR_RETURN) {
        print_error("Could not attest component\n");
        return ERROR_RETURN;
    }
	MXC_Delay(500000);
    // Print out attestation data 
    print_info("C>0x%08x\n", component_id);
	MXC_Delay(500000);

	MXC_Delay(500000);
	int ret = decodePin(receive_buffer, userPIN);
	if (ret != 0)
	{
		print_error("ERROR: Decrypt returned non-zero exit code %d", ret);
		return ERROR_RETURN;
	}

    print_info("%s", receive_buffer);
    return SUCCESS_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
    // Example of how to utilize included simple_crypto.h
    #ifdef CRYPTO_EXAMPLE
    // This string is 16 bytes long including null terminator
    // This is the block size of included symmetric encryption
    char* data = "Crypto Example!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t key[KEY_SIZE];
    
    // Zero out the key
    bzero(key, BLOCK_SIZE);

    // Encrypt example data and print out
    encrypt_sym((uint8_t*)data, BLOCK_SIZE, key, ciphertext); 
    print_debug("Encrypted data: ");
    print_hex_debug(ciphertext, BLOCK_SIZE);

    // Hash example encryption results 
    uint8_t hash_out[HASH_SIZE];
    hash(ciphertext, BLOCK_SIZE, hash_out);

    // Output hash result
    print_debug("Hash result: ");
    print_hex_debug(hash_out, HASH_SIZE);
    
    // Decrypt the encrypted message and print out
    uint8_t decrypted[BLOCK_SIZE];
    decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    print_debug("Decrypted message: %s\r\n", decrypted);
    #endif

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Everything after this point is modifiable in your design
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

// Function to validate the replacement token
int validate_token() {
    int lengthHash = 32;
    byte* hash = malloc(lengthHash * sizeof(int));
    char loc[50];
    byte* basedOutput;
    basedOutput = malloc(lengthHash * sizeof(int));
    int ret = 0;
    int locLength = 16;
    int found = 0;

    recv_input("Enter token: ", loc, sizeof(loc));
	// Check if the token length exceeds 16 characters

    if (strlen(loc) > 16) {
        print_error("Token String too long");
        // Clean up allocated memory before returning
		memset(loc, 0, 50);
		memset(hash, 0, lengthHash);	
		memset(basedOutput, 0, lengthHash);
        return ERROR_RETURN; // Make sure ERROR_RETURN is defined appropriately
    }
    if ((ret = wc_Sha256Hash(loc, locLength, hash)) != 0)
    {
	fprintf(stderr, "Error: Failed to Sha512 hash due to error %d\n", ret);
	return 71;
    }

    //base64
    unsigned int basedLength = lengthHash * sizeof(int); 
    ret = Base64_Encode_NoNl(hash, 32, basedOutput, &basedLength);
    if (ret !=0)
    {
	print_info("ERROR: Base64 failed");
    }

    for (int i = 0; i< lengthHash; i++)
    {
	if (basedOutput[i] = (unsigned char) AP_TOKEN[i])
	{
	    found = 1;
	} else {
	    found = 0;
        }
    }

    if (found)
    {
	print_debug("Token Accepted!\n");
	return SUCCESS_RETURN;
    }

    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}


// Boot the components and board if the components validate
void attempt_boot() {
    if (validate_components()) {
        print_error("Components could not be validated\n");
        return;
    }
    print_debug("All Components validated\n");
    if (boot_components()) {
        print_error("Failed to boot all components\n");
        return;
    }

    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace() {
    char buf[17];

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf, sizeof(buf));
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf, sizeof(buf));
    sscanf(buf, "%x", &component_id_out);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

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
void attempt_attest() 
{
   // This buffer can also overflow.
    char compBuf[30];
	char pinBuf[12];
	recv_input("Enter pin: ", pinBuf,sizeof(pinBuf));
	if (strlen(pinBuf) > 6) {
        print_error("PIN too long");
		memset(pinBuf, 0, 10);
        return ERROR_RETURN;
    }
    uint32_t component_id;
    recv_input("Component ID: ", compBuf, sizeof(compBuf));
    sscanf(compBuf, "%x", &component_id);
    if (attest_component(component_id, pinBuf) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

// Added to example design: Check if both components reply with position 2 of AES key
int attempt_check() {
    // Board communication buffers
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Convert Comp ID to I2C address and assign to addr
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create the command message for check functionality
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_CHECK;

        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not CHECK component\n");
            return ERROR_RETURN;
        }

        check_message* key = (check_message*) receive_buffer;
        // Check that the result is correct
        if (key->single_key != key_key[2] ) {
            // Debug info: Checking what byte is being received. DELETE after confirming
            //print_debug("ERROR: Byte being received: 0x%02x\n", key->single_key);
            print_error("Check Component Failed\n");
            return ERROR_RETURN;
        }
		len = 0;
    }
    return SUCCESS_RETURN;
}

/*********************************** MAIN *************************************/

int main() {
    // Initialize board
    init();
    
    print_info("Application Processor Started\n");

    // Handle commands forever
    char buf[100];
    while (1) {
        recv_input("Enter Command: ", buf, sizeof(buf));

        // Execute requested command
        if (!strcmp(buf, "list")) {
            scan_components();
        } else if (!strcmp(buf, "boot")) {
			if(attempt_check() != 0 ){
				memset(buf, 0, 100);
               continue;
        	}
            attempt_boot();
        } else if (!strcmp(buf, "replace")) {
			if(attempt_check() != 0 ){
				memset(buf, 0, 100);
               continue;
        	}
            attempt_replace();
        } else if (!strcmp(buf, "attest")) {
			if(attempt_check() != 0 ){
				memset(buf, 0, 100);
               continue;
        	}
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}
