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
#include "simple_crypto.h"

#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#endif

#include "lp.h"
#include "mxc_sys.h"
#include "nvic_table.h"

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

//Foreward declarations
//Calculates checksum for messages
void CRC16(uint8_t* buffer,int length, uint8_t* pnSum1, uint8_t* pnSum2);
//Transfers encryption key to components
void TransferKey(i2c_addr_t addr);
//This function will determine the delay before another PIN or token attempt can be made.
//Each time 3 attempts is reached, this is called. It will shift g_nRetryFlags 1 bit left
//then check to see the lowest bit that is set. b1 = 5 min, b2 = 15 min, b3 = 45 min....
void SetAttemptDelay();

// Parameters for Continuous timer used for retry timeout
#define CONT_CLOCK_SOURCE MXC_TMR_8M_CLK 
#define CONT_FREQ 1 // (Hz)
#define CONT_TIMER MXC_TMR1 


/********************************* CONSTANTS **********************************/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

#define FLASH_RETRY_FLAGS_ADDR	0x10046000								//Store retry flags at first available page boundry
#define MAX_RETRIES		1

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. This is not utilized by the example
// design but can be utilized by your design.

#define MAX_I2C_ADDRESS	0x78											//0x77 is highest
#define ATTEMPT_RETRY_BASE_SECONDS	5									//300 seconds(5 minutes)
																		//Due to timing requirements, I had to set to 5

//In order to secure the existing protocol, these macros will be used in secure send/receive to 
//reformat the message before encryption and after decryption

#define PROTOCOL_OFFSET		3											//Move data 3 bytes
#define CHECKSUM_BYTES		2											//2 checksum bytes
#define PROROCOL_LEN_ADD	PROTOCOL_OFFSET + CHECKSUM_BYTES


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

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;

uint8_t 	g_nSequenceNumber[MAX_I2C_ADDRESS];							//Sequence number for each component
uint8_t 	g_nKey[KEY_SIZE];											//Encryption key 
bool		g_bKeySet[MAX_I2C_ADDRESS];									//Set to show it is okay to send encrypted data

const char* g_pszKeyRecievedMessage = "Key Received";					//Sent by component when key is received
																		//Reply is encrypted so it will not decrypt
																		//properly if key is not correct
uint32_t g_nRetryTimeout=0;												//Retry timeout for PIN/Token entry
uint32_t g_nFreeRunningTimer=0;											//Free running timer to compare to g_nRetryTimeout
uint32_t g_nRetryFlags;													//Each bit cleared adds 5 minutes to the retry time
																		//Read/stroed from/to Flash
uint32_t g_nRetryCount=0;
bool g_bReceivedMessageWasEncrypted;									//Used to determine if the message was encrypted if this is what
																		//I am expecting.
bool g_bSystemIsBooted;													//Since I want to receive encrypted messages and unencrypted
																		//messages before boot and only encrypted after boot, I need
																		//this flag and g_bReceivedMessageWasEncrypted

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
int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) 
{
    uint8_t nSumLow, nSumHigh;
	uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
    
	//First I need to reformat the message by shifting the current data to a higher index
    for(int i = len - 1; i >= 0; i--)
        buffer[i+PROTOCOL_OFFSET] = buffer[i];    
    len+=PROROCOL_LEN_ADD;												//Add room for length byte, seq number, and checksum
	len += BLOCK_SIZE - ((len - 2) % BLOCK_SIZE);						//Add bytes to make length multiple of BLOCK_SIZE
																		//First 2 bytes are not encrypted.

	//Now add encryption byte, length and seq number
    buffer[0] = COMPONENT_MSG_ENC;
    buffer[1] = len;
    buffer[2] = g_nSequenceNumber[address];

	//Calculate checksum and add to message
    CRC16(buffer,len - 2, &nSumLow, &nSumHigh);
    buffer[len-2]=nSumLow;
    buffer[len-1]=nSumHigh;

	//Encrypt and send
	memcpy(transmit_buffer,buffer,len);
	encrypt_sym(&transmit_buffer[2], len-2, g_nKey, &buffer[2]); 
	
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
int secure_receive(i2c_addr_t address, uint8_t* buffer) 
{
    int len = poll_and_receive_packet(address, buffer);
	uint8_t nSumLow, nSumHigh;
	g_bReceivedMessageWasEncrypted = false;
    
    if(len>0)
    {
        if(buffer[0] == COMPONENT_MSG_ENC || g_bSystemIsBooted)
		{
			uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
			
			decrypt_sym(&buffer[2], len - 2, g_nKey, receive_buffer);	//Decrypt message			
			memcpy(&buffer[2],receive_buffer,len - 2);
			
			CRC16(buffer,len - 2, &nSumLow, &nSumHigh);

			//Validate checksum and then reformat message
			if(nSumLow == buffer[len -2] && nSumHigh == buffer[len - 1] && g_nSequenceNumber[address] == buffer[2])
			{
				for(int i = PROTOCOL_OFFSET; i < len; i++)
				    buffer[i - PROTOCOL_OFFSET] = buffer[i];    
				len-=PROROCOL_LEN_ADD;									//decrease length for length byte, seq number, and checksum 
				g_bReceivedMessageWasEncrypted = true;				
			}
			else
			{
				len = ERROR_RETURN;
			}
			g_nSequenceNumber[address]++;								//Increment even if bad because component did when sent			
		}
    }
    return len;
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
int get_provisioned_ids(uint32_t* buffer) 
{
    memcpy(buffer, flash_status.component_ids, flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

/********************************* UTILITIES **********************************/

/***********************************Timer**************************************/
//Increments every one second
void ContinuousTimerHandler()
{
    // Clear interrupt
    MXC_TMR_ClearFlags(CONT_TIMER);
	if(g_nFreeRunningTimer != 0xFFFFFFFF)								//Do not wrap the timer
		g_nFreeRunningTimer++;
	LED_Toggle(LED1);
}

void ContinuousTimer()
{
    mxc_tmr_cfg_t tmr;
    uint32_t periodTicks = MXC_TMR_GetPeriod(CONT_TIMER, CONT_CLOCK_SOURCE, 128, CONT_FREQ);

    MXC_TMR_Shutdown(CONT_TIMER);

    tmr.pres = TMR_PRES_128;
    tmr.mode = TMR_MODE_CONTINUOUS;
    tmr.bitMode = TMR_BIT_MODE_16B;
    tmr.clock = CONT_CLOCK_SOURCE;
    tmr.cmp_cnt = periodTicks; //SystemCoreClock*(1/interval_time);
    tmr.pol = 0;

    if (MXC_TMR_Init(CONT_TIMER, &tmr, true) != E_NO_ERROR) 
	{
        print_error("Failed Continuous timer Initialization.\n");
        return;
    }
}

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() 
{

    // Enable global interrupts    
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
	flash_simple_read(FLASH_RETRY_FLAGS_ADDR, &g_nRetryFlags, sizeof(uint32_t));

	//If g_nRetryFlags is not 0xFFFFFFFF AP was shut down while timing a retry timer, so start timing. 
	if(g_nRetryFlags != 0xFFFFFFFF)
	{
		SetAttemptDelay();
		g_nRetryCount = MAX_RETRIES;
	}


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

    //Init flags to false
	memset(g_bKeySet,0,sizeof(bool) * MAX_I2C_ADDRESS);

	g_bSystemIsBooted = false;											//Not booted

	srand(time(NULL));													//Seed random num generator
    bzero(g_nKey, BLOCK_SIZE);											//Zero out the key
	for(int i = 0; i < KEY_SIZE;i++)									//Create a 16 byte random key
		g_nKey[i] = rand() % 256;

	MXC_NVIC_SetVector(TMR1_IRQn, ContinuousTimerHandler);				//Set up timer for retries
 	NVIC_EnableIRQ(TMR1_IRQn);
 	ContinuousTimer();
    
    // Initialize board link interface
    board_link_init();
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive, uint8_t len, bool bSecure) 
{
    // Send message
    int result;
	if(!bSecure)
		result = send_packet(addr, len, transmit);
	else
		result = secure_send(addr, transmit, len);
    if (result == ERROR_RETURN) 
        return ERROR_RETURN;
    
    // Receive message
	len = secure_receive(addr, receive);

    if (len == ERROR_RETURN) 
        return ERROR_RETURN;

    return len;
}

/******************************** COMPONENT COMMS ********************************/

//Unchanged...
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
        int len = issue_cmd(addr, transmit_buffer, receive_buffer, sizeof(uint8_t), false);

        // Success, device is present
        if (len > 0) {
            scan_message* scan = (scan_message*) receive_buffer;
            print_info("F>0x%08x\n", scan->component_id);
        }
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

int validate_components() 
{
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send validate command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) 
	{
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

		if(!g_bKeySet[addr])											//Since I am getting ready to boot, have I set the key
			TransferKey(addr);

    	if(g_bKeySet[addr])												//Did the key get set??
		{
		    // Create command message
		    command_message* command = (command_message*) transmit_buffer;
		    command->opcode = COMPONENT_CMD_VALIDATE;
		    
		    // Send out command and receive result
		    int len = issue_cmd(addr, transmit_buffer, receive_buffer, sizeof(uint8_t), true);
		    if (len == ERROR_RETURN || !g_bReceivedMessageWasEncrypted) 
			{
		        print_error("Could not validate component\n");
		        return ERROR_RETURN;
		    }

		    validate_message* validate = (validate_message*) receive_buffer;
		    // Check that the result is correct
		    if (validate->component_id != flash_status.component_ids[i]) 
			{
		        print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
		        return ERROR_RETURN;
		    }
		}
		else
		{
			print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
		    return ERROR_RETURN;
		}
    }
    return SUCCESS_RETURN;
}

int boot_components() 
{
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) 
	{
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
		
		if(!g_bKeySet[addr])											//Should have been set in validate_components, but...
			TransferKey(addr);

    	if(g_bKeySet[addr])												//If not set do not even try to boot.
		{        
		    // Create command message
		    command_message* command = (command_message*) transmit_buffer;
		    command->opcode = COMPONENT_CMD_BOOT;
		    
		    // Send out command and receive result
		    int len = issue_cmd(addr, transmit_buffer, receive_buffer, sizeof(uint8_t), true);
		    if (len == ERROR_RETURN || !g_bReceivedMessageWasEncrypted) 
			{
		        print_error("Could not boot component\n");
		        return ERROR_RETURN;
		    }

		    // Print boot message from component
		    print_info("0x%08x>%s\n", flash_status.component_ids[i], receive_buffer);
		}
		else
		{
			print_error("Could not boot component\n");
		    return ERROR_RETURN;
		}
    }
    return SUCCESS_RETURN;
}

int attest_component(uint32_t component_id) 
{
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);
	if((addr > 0x77 || addr == 0x18 || addr == 0x28 || addr == 0x36))
	{
		// 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
		print_error("Component ID 0x%08x is not valid ID.\r\n",
            component_id);
		return ERROR_RETURN;
	}

    if(!g_bKeySet[addr])												//To keep attestation data secure, send encrypted
		TransferKey(addr);												//Send key if not already.

    if(g_bKeySet[addr])													//Did the key get set?
    {
    	// Create command message
    	command_message* command = (command_message*) transmit_buffer;
    	command->opcode = COMPONENT_CMD_ATTEST;

    	// Send out command and receive result
    	int len = issue_cmd(addr, transmit_buffer, receive_buffer, 1, true);
    	if (len == ERROR_RETURN || !g_bReceivedMessageWasEncrypted) 
		{
            print_error("Could not attest component\n");
            return ERROR_RETURN;
    	}

    	// Print out attestation data 
    	print_info("C>0x%08x\n", component_id);
    	print_info("%s", receive_buffer);
    	return SUCCESS_RETURN;
	}
	else
	{
		print_error("Could not attest component. Enc key not set\n");
        return ERROR_RETURN;
	}

}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() 
{
    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Everything after this point is modifiable in your design
    // LED loop to show that boot occurred
	char buf[100];
    while (1) 
	{
		recv_input("Enter Command: ", buf);

        // Just for testing...
        if (!strcmp(buf, "attest")) 
            attempt_attest();

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

//This function will determine the delay before another PIN or token attempt can be made.
//Each time 3 attempts is reached, this is called. It will shift g_nRetryFlags 1 bit left
//then check to see the lowest bit that is set. b1 = 5 min, b2 = 15 min, b3 = 45 min....
void SetAttemptDelay()
{
	//print_debug("Timer started\n");
	//print_hex_debug(&g_nRetryFlags, sizeof(uint32_t));	

	int i = 0;
	g_nRetryFlags = g_nRetryFlags << 1;									//Shift out 1 bit

	//flash_simple_write(FLASH_RETRY_FLAGS_ADDR, &g_nRetryFlags, sizeof(g_nRetryFlags));

	for(; i < 32; i++)
	{
		//If this bit is set, delay is i * i * 300 seconds(5 min)
		if(g_nRetryFlags & (1 << i))										
			break;
	}
	//g_nRetryTimeout = i * i * ATTEMPT_RETRY_BASE_SECONDS;				//After 32 attempts, timeout will be 85 hours
	g_nRetryTimeout = ATTEMPT_RETRY_BASE_SECONDS;						//Due to timing requirements, can only set to 5 seconds
	g_nFreeRunningTimer = 0;
	//print_debug("Timer started\n");
	//print_hex_debug(&g_nRetryFlags, sizeof(uint32_t));														
}

//When a valid PIM or token is entered, this will be called to reset the flags so the attempt timer
//will start over next time the retry count is met
void ResetAttemptDelay()
{
	//print_debug("Timer reset\n");
	//print_hex_debug(&g_nRetryFlags, sizeof(uint32_t));

	g_nRetryCount = 0;
	if(g_nRetryFlags != 0xFFFFFFFF)
	{
		//flash_simple_erase_page(FLASH_RETRY_FLAGS_ADDR);		
		g_nRetryFlags=0xFFFFFFFF;
		//flash_simple_read(FLASH_RETRY_FLAGS_ADDR, &g_nRetryFlags, sizeof(uint32_t));
	}
	//print_hex_debug(&g_nRetryFlags, sizeof(uint32_t));
}

// Compare the entered PIN to the correct PIN
int validate_pin() 
{
	if(g_nRetryCount >= MAX_RETRIES && g_nFreeRunningTimer < g_nRetryTimeout)
	{
		print_error("You entered an invalid PIN. You must wait %d seconds!\n",(g_nRetryTimeout - g_nFreeRunningTimer));
    	return ERROR_RETURN;
	}
	else
	{
		if(g_nRetryCount >= MAX_RETRIES)									//Timer must have expired so reset counter
			g_nRetryCount = 0;

		char buf[50];
		recv_input("Enter pin: ", buf);
		if (!strcmp(buf, AP_PIN)) 
		{
			ResetAttemptDelay();
		    print_debug("Pin Accepted!\n");
		    return SUCCESS_RETURN;
		}
		if(++g_nRetryCount >= MAX_RETRIES)
			SetAttemptDelay();
	}
    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() 
{
	if(g_nRetryCount >= MAX_RETRIES && g_nFreeRunningTimer < g_nRetryTimeout)
	{
		print_error("You have entered an invalid token. You must wait %d seconds!\n",(g_nRetryTimeout - g_nFreeRunningTimer));
    	return ERROR_RETURN;
	}
	else
	{
		if(g_nRetryCount >= MAX_RETRIES)									//Timer must have expired so reset counter
			g_nRetryCount = 0;

		char buf[50];
		recv_input("Enter token: ", buf);
		if (!strcmp(buf, AP_TOKEN)) 
		{
			ResetAttemptDelay();
		    print_debug("Token Accepted!\n");
		    return SUCCESS_RETURN;
		}
		if(++g_nRetryCount >= MAX_RETRIES)
			SetAttemptDelay();
	}
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() 
{
    if (validate_components()) 
	{
        print_error("Components could not be validated\n");
        return;
    }
    print_debug("All Components validated\n");
    if (boot_components()) 
	{
        print_error("Failed to boot all components\n");
        return;
    }    
    
    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");

	// Boot
	g_bSystemIsBooted = true;											//Booted.
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace() 
{
    char buf[50];

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf);
    sscanf(buf, "%x", &component_id_out);

	i2c_addr_t addr = component_id_to_i2c_addr(component_id_in);

	//Make sure the address is valid...
	if((addr > 0x77 || addr == 0x18 || addr == 0x28 || addr == 0x36))
	{
		// 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
		print_error("Component ID 0x%08x is not valid ID.\r\n",
            component_id_out);
		return;
	}


    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) 
	{
        if (flash_status.component_ids[i] == component_id_out) 
		{
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
			
            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
                    component_id_in);
            print_success("Replace\n");

			i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
			g_bKeySet[addr] = false;

            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",
            component_id_out);
}

// Attest a component if the PIN is correct
void attempt_attest() {
    char buf[50];

    if (validate_pin()) {
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", buf);
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

/*********************************** MAIN *************************************/

int main() 
{
    // Initialize board
    init();

    // Handle commands forever
    char buf[100];
    while (1) {
        recv_input("Enter Command: ", buf);

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

//CRC16 for encrypted messages
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

void TransferKey(i2c_addr_t addr)
{
	uint8_t enckey[KEY_SIZE];
	encrypt_sym((uint8_t*)g_nKey, KEY_SIZE, (uint8_t*)secret, enckey); 	//Encrypt my key with secret
	uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
	uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];

    // Create command message 
    command_message* command = (command_message*) transmit_buffer;
    command->opcode = COMPONENT_SET_KEY;
	memcpy(&transmit_buffer[1],(uint8_t*)enckey,KEY_SIZE);
    
	g_nSequenceNumber[addr] = addr;										//Init seq number
    
   	// Send out command and receive result
   	int len = issue_cmd(addr, transmit_buffer, receive_buffer, KEY_SIZE + 1, false);

   	if (len > 0) 
	{ 
		if(strcmp(g_pszKeyRecievedMessage, (char*)receive_buffer) == 0)
		{
			g_bKeySet[addr] = true;			
		}
    }    
}

