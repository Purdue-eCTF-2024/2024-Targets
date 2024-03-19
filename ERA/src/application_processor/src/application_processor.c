/**
 * @file application_processor.c
 * @author Jacob Doll
 * @edited by ERA_Team
 * @brief eCTF AP secure code
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
#include "host_messaging.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

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
#include "global_secrets.h"
#include "aes.h"
/********************************* CONSTANTS **********************************/
char pin[65];
void read_pin()
{ for(int i=0;i<64;i++) {pin[i]=AP_PIN[i]; }pin[64]='\0';}
char token[65];
void read_token()
{ for(int i=0;i<64;i++) {token[i]=AP_TOKEN[i];} token[64]='\0'; }
char pin_salt[64];
void read_pin_salt()
{ for(int i=0;i<sizeof(PIN_salt);i++) pin_salt[i]=PIN_salt[i]; }
char token_salt[64];
void read_token_salt()
{ for(int i=0;i<sizeof(TOKEN_salt);i++) token_salt[i]=TOKEN_salt[i]; }
// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1
/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// we used it to store and send a hash value that allows components to 
// verify AP validity
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;
//Data structure for sending and receiving messages 
//Authenticity allows to send 65 bytes which stores a hash value define the sender
//Integrity allows te send a hash of 64 bytes that helps to verify integrity
//message stores the clear message

typedef struct {
    uint8_t authenticity[65];
    uint8_t message[65];
    uint8_t integrity[65];   
}secure_message;

typedef struct {
	uint8_t loc[65];
	uint8_t date[65];
	uint8_t cust[65];
}attest_data;

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
    COMPONENT_CMD_SIGN
} component_cmd_t;
typedef unsigned char byte;
/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;
#define MAX_STRING_LENGTH 20

/******************************* ACQUIRED FUNCTIONS *********************************/

unsigned getEntropyFromAddress(void* ptr) {
    return (unsigned)((uintptr_t)ptr);
}

void arbitraryOperation() {
    // Combine time, process ID, and additional entropy
    unsigned seed = (unsigned)time(NULL) ^ (unsigned)getpid() ^ getEntropyFromAddress((void*)&seed);

    // Seed the random number generator
    srand(seed);

    // Generate a random number between 0 and 20
    int* randomNumber = (int *)malloc(sizeof(int));
    *randomNumber=rand() % 21;

    // Perform an arbitrary operation based on the generated number
    switch (*randomNumber) {
        case 0: {
            // Sum of two random numbers
            int *num1 = (int *)malloc(sizeof(int));
            int *num2 = (int *)malloc(sizeof(int));
            *num1 = rand() % 100;
            *num2 = rand() % 100;
            int *sum = (int *)malloc(sizeof(int));
            *sum = *num1 + *num2;
            free(num1);
            free(num2);
            free(sum);
            free(randomNumber);
            break;
        }
        case 1: {
            // Concatenation of two random strings
            char *str1 = (char *)malloc((MAX_STRING_LENGTH + 1) * sizeof(char));
            char *str2 = (char *)malloc((MAX_STRING_LENGTH + 1) * sizeof(char));
            sprintf(str1, "String%d", rand() % 10);
            sprintf(str2, "String%d", rand() % 10);
            char *concatenatedString = (char *)malloc((2 * MAX_STRING_LENGTH + 1) * sizeof(char));
            strcpy(concatenatedString, str1);
            strcat(concatenatedString, str2);
            free(str1);
            free(str2);
            free(concatenatedString);
            free(randomNumber);
            break;
        }
        case 2: {
            // Converting random string to bytes
            char *randomString = (char *)malloc((MAX_STRING_LENGTH + 1) * sizeof(char));
            sprintf(randomString, "Random%d", rand() % 10);
            unsigned char *bytes = (unsigned char *)malloc((strlen(randomString) + 1) * sizeof(unsigned char));
            for (int i = 0; i < strlen(randomString); i++) {
                bytes[i] = randomString[i];
            }
            bytes[strlen(randomString)] = '\0';
            free(randomString);
            free(bytes);
            free(randomNumber);
            break;
        }
        case 3: {
            // Multiplication of two random numbers
            int *num1 = (int *)malloc(sizeof(int));
            int *num2 = (int *)malloc(sizeof(int));
            *num1 = rand() % 20;
            *num2 = rand() % 20;
            int *product = (int *)malloc(sizeof(int));
            *product = *num1 * *num2;
            free(num1);
            free(num2);
            free(product);
            free(randomNumber);
            break;
        }
        case 4: {
            // Random floating-point number between 0 and 1
            float *randFloat = (float *)malloc(sizeof(float));
            *randFloat = (float)rand() / RAND_MAX;
            free(randFloat);
            free(randomNumber);
            break;
        }
        case 5: {
            // Generating a random uppercase letter
            char *uppercaseLetter = (char *)malloc(sizeof(char));
            *uppercaseLetter = 'A' + rand() % 26;
            free(uppercaseLetter);
            free(randomNumber);
            break;
        }
        case 6: {
            // Generating a random lowercase letter
            char *lowercaseLetter = (char *)malloc(sizeof(char));
            *lowercaseLetter = 'a' + rand() % 26;
            free(lowercaseLetter);
            free(randomNumber);
            break;
        }
        case 7: {
            // Generating a random ASCII character
            char *asciiChar = (char *)malloc(sizeof(char));
            *asciiChar = rand() % 128;
            free(asciiChar);
            free(randomNumber);
            break;
        }
        case 8: {
            // Generating a random boolean value (0 or 1)
            int *randomBool = (int *)malloc(sizeof(int));
            *randomBool = rand() % 2;
            free(randomBool);
            free(randomNumber);
            break;
        }
        case 9: {
            // Generating a random even number between 0 and 100
            int *evenNum = (int *)malloc(sizeof(int));
            *evenNum = (rand() % 51) * 2;
            free(evenNum);
            free(randomNumber);
            break;
        }
        case 10: {
            // Generating a random odd number between 0 and 100
            int *oddNum = (int *)malloc(sizeof(int));
            *oddNum = (rand() % 50) * 2 + 1;
            free(oddNum);
            free(randomNumber);
            break;
        }
        case 11: {
            // Generating a random hexadecimal digit
            char *hexDigit = (char *)malloc(sizeof(char));
            *hexDigit = rand() % 16;
            free(hexDigit);
            free(randomNumber);
            break;
        }
        case 12: {
            // Generating a random positive integer less than 1000
            int *randomInt = (int *)malloc(sizeof(int));
            *randomInt = rand() % 1000;
            free(randomInt);
            free(randomNumber);
            break;
        }
        case 13: {
            // Generating a random negative integer less than -1000
            int *negativeInt = (int *)malloc(sizeof(int));
            *negativeInt = -1 * (rand() % 1000);
            free(negativeInt);
            free(randomNumber);
            break;
        }
        case 14: {
            // Reversing a random string
            char *originalStr = (char *)malloc((MAX_STRING_LENGTH + 1) * sizeof(char));
            char *reversedStr = (char *)malloc((MAX_STRING_LENGTH + 1) * sizeof(char));
            sprintf(originalStr, "String%d", rand() % 10);
            for (int i = strlen(originalStr) - 1, j = 0; i >= 0; i--, j++) {
                reversedStr[j] = originalStr[i];
            }
            reversedStr[strlen(originalStr)] = '\0';
            free(originalStr);
            free(reversedStr);
            free(randomNumber);
            break;
        }
        case 15: {
            // Generating a random lowercase vowel
            char *lowercaseVowel = (char *)malloc(sizeof(char));
            *lowercaseVowel = "aeiou"[rand() % 5];
            free(lowercaseVowel);
            free(randomNumber);
            break;
        }
        case 16: {
            // Generating a random uppercase vowel
            char *uppercaseVowel = (char *)malloc(sizeof(char));
            *uppercaseVowel = "AEIOU"[rand() % 5];
            free(uppercaseVowel);
            free(randomNumber);
            break;
        }
        case 17: {
            // Generating a random phone number
            char *phoneNumber = (char *)malloc(15 * sizeof(char));
            sprintf(phoneNumber, "(%03d) %03d-%04d", rand() % 1000, rand() % 1000, rand() % 10000);
            free(phoneNumber);
            free(randomNumber);
            break;
        }
        case 18: {
            // Generating a random date (YYYY-MM-DD)
            char *date = (char *)malloc(11 * sizeof(char));
            sprintf(date, "%04d-%02d-%02d", 1970 + rand() % 55, 1 + rand() % 12, 1 + rand() % 28);
            free(date);
            free(randomNumber);
            break;
        }
        case 19: {
            // Generating a random IP address
            char *ipAddress = (char *)malloc(16 * sizeof(char));
            sprintf(ipAddress, "%d.%d.%d.%d", rand() % 256, rand() % 256, rand() % 256, rand() % 256);
            free(ipAddress);
            free(randomNumber);
            break;
        }
        default:
            char *randomSentence = (char *)malloc((MAX_STRING_LENGTH * 5 + 1) * sizeof(char));
            sprintf(randomSentence, "This is a default case with a random number: %d", rand() % 100);
            free(randomSentence);
            free(randomNumber);
            break;
    }
}

int secure_compare(const char *s1, const char *s2,size_t n) {
    if (n == 0)
		return (0);

    int result = 0;

    for (size_t i = 0; i < n; i++) {
	arbitraryOperation();
        result |= (s1[i] ^ s2[i]);
    }

    return result;
}
//string to hex_string
char* string_to_hex(const char* input) {
    size_t len = strlen(input);
    char* hex_string = (char*)malloc(2 * len + 1); // Each character in the input string corresponds to two hex characters, plus one for the null terminator

    if (hex_string == NULL) {
        // Handle memory allocation failure
        return NULL;
    }

    for (size_t i = 0; i < len; i++) {
        sprintf(hex_string + 2 * i, "%02X", (unsigned char)input[i]); // Convert each character to its hexadecimal representation
    }

    // Convert hex string to lowercase
    for (size_t i = 0; i < 2 * len; i++) {
        hex_string[i] = tolower(hex_string[i]);
    }

    hex_string[2 * len] = '\0'; // Null-terminate the hexadecimal string
    return hex_string;
}
// hex string to integer
int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// hex string to bytes value
void hex_string_to_bytes(char* hex_str, uint8_t* bytes) {
    size_t num_bytes = strlen(hex_str) / 2;
    for (size_t i = 0; i < num_bytes; i++) {
        bytes[i] = hex_char_to_int(hex_str[i * 2]) * 16 + hex_char_to_int(hex_str[i * 2 + 1]);
    }
}


// bytes value to hex string
void bytes_to_hex_string(uint8_t* bytes, size_t num_bytes, char* hex_str) {
    for (size_t i = 0; i < num_bytes; i++) {
        sprintf(&hex_str[i * 2], "%02x", bytes[i]);
    }
    hex_str[num_bytes * 2] = '\0'; // Null-terminate the string
}
char* extract_key(const char* secret) {
    char* key = malloc(17); 
    
    if (strlen(secret) >= 16) {
        for (int i = 0; i < 16; i++) {
            key[i] = secret[i];
        }
    } else {
        for (int i = 0; i < strlen(secret); i++) {
            key[i] = secret[i];
        }

        for (int i = strlen(secret); i < 16; i++) {
            key[i] = '.';
        }
    }
    
    key[16] = '\0'; 
    return key;
}

 uint32_t i2c_addr_to_cnt_id(i2c_addr_t addr){
        for (unsigned i = 0; i < flash_status.component_cnt; i++){
        if (component_id_to_i2c_addr(flash_status.component_ids[i])==addr)
        {return flash_status.component_ids[i];}}}
        


/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
*/
int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    //copying buffer
    uint8_t buffer_copy1[MAX_I2C_MESSAGE_LEN-1];
    uint8_t buffer_copy2[MAX_I2C_MESSAGE_LEN-1];  
    memcpy(&buffer_copy1,buffer,len);
    memcpy(&buffer_copy2,buffer,len);
    secure_message* secure=(secure_message*) buffer_copy1;
    
    //authenticity
    char ap_buf[65];
    uint32_t addr=i2c_addr_to_cnt_id(address);
    sprintf(ap_buf,"%s%x%s",AP_secret_id,addr,COMP_secret_id);
    char* ap_hash=hashme256(&ap_buf);
    sprintf((char*)secure->authenticity,"%s",ap_hash);
    secure->authenticity[64]='\0';
    free(ap_hash);
    
    //integrity
    memcpy(&secure->message,buffer,len);    
    char integ[64];
    sprintf(integ,"%i%s",*buffer_copy2,SECRET_messaging);
    char* integ_hash=hashme256(&integ);
    sprintf((char*)secure->integrity,"%s",integ_hash);
    secure->integrity[64]='\0';
    free(integ_hash);
	
    //sending data
    int ret=send_packet(address,MAX_I2C_MESSAGE_LEN-1, buffer_copy1);
    return ret;
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
*/
int secure_receive(i2c_addr_t address, uint8_t* buffer) {
    uint8_t receive_buffer1[MAX_I2C_MESSAGE_LEN];
    //receiving
    int ret=poll_and_receive_packet(address,receive_buffer1);
	
    //constructing message form
    secure_message* secure=(secure_message*) receive_buffer1;

    //authenticity test
    char comp_buf[65];
    uint32_t addr=i2c_addr_to_cnt_id(address);
    sprintf(comp_buf,"%s%x%s",COMP_secret_id,addr,AP_secret_id);
    char* comp_hash=hashme256(&comp_buf);
    if(secure_compare(comp_hash,(char*)secure->authenticity,65)){
    	print_error("failed!!!\n");
    	free(buffer);
    	return ERROR_RETURN;
    }
    free(comp_hash);
	
    //integrity test
    char integ[65];
    sprintf(integ,"%i%s",*secure->message,SECRET_messaging);
    char* integ_hash=hashme256(&integ);
    if(secure_compare(integ_hash,(char*)secure->integrity,65)){
    	free(buffer);
    	print_error("failed!!!\n");
    	return ERROR_RETURN;
    }
    free(integ_hash);
    secure->message[64]='\0';
    //extracting message
    memcpy(buffer,secure->message,65);
    return ret;
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
*/
int get_provisioned_ids(uint32_t* buffer) {
    memcpy(buffer, flash_status.component_ids, flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

/********************************* UTILITIES **********************************/

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() {
    //variables initialisaton
	read_pin_salt();
	read_token_salt();
    // Combine time, process ID, and additional entropy
    unsigned seed = (unsigned)time(NULL) ^ (unsigned)getpid() ^ (unsigned long)&seed;

    // Seed the random number generator
    srand(seed);
    if(rand()%21 >10)
    {read_pin();
     read_token(); }
    else
    {read_token();
     read_pin(); }
    // Enable global interrupts    
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
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
    int result = send_packet(addr, (MAX_I2C_MESSAGE_LEN-1)*sizeof(uint8_t), transmit);
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
    char id[50];
    sprintf(id,"%s",AP_secret_id);    
    char* hash=hashme256(&id);
    sprintf((char*)command->params,"%s",hash);
    free(hash);
	      
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
    char id[50];
    sprintf(id,"%s",AP_secret_id);    
    char* hash=hashme256(&id);
    sprintf((char*)command->params,"%s",hash);
            free(hash);
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

int sign_components() {
    if (validate_components()) {
        print_error("Components could not be validated\n");
        return ERROR_RETURN;}
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send validate command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_SIGN;
	char id2[50];
	sprintf(id2,"%s",AP_secret_id);    
	char* hash2=hashme256(&id2);
	sprintf((char*)command->params,"%s",hash2);
	free(hash2);
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
	    MXC_Delay(MXC_DELAY_MSEC(3000));
            print_error("Could not sign component\n");
            return ERROR_RETURN;
        }
        char id[50];
        sprintf(id,"%x",flash_status.component_ids[i]);
        strcat(id,COMP_secret_id);
        char* hash=hashme256(&id);
        
        // Check that the result is correct
        if (secure_compare((char*)receive_buffer,hash,65)) {
	   free(hash);
	    MXC_Delay(MXC_DELAY_MSEC(3000));
            print_error("Component ID: 0x%08x didn't sign!!!\n", flash_status.component_ids[i]);
            return ERROR_RETURN;
        } 
        free(hash);
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
        char id[50];
        sprintf(id,"%s",AP_secret_id);
        
        char* hash=hashme256(&id);
        sprintf((char*)command->params,"%s",hash);
	free(hash);
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        
        if (len == ERROR_RETURN) {
	    MXC_Delay(MXC_DELAY_MSEC(3000));
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i], receive_buffer);
    }
    return SUCCESS_RETURN;
}

int attest_component(uint32_t component_id) {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Create command message
    command_message* command = (command_message*) transmit_buffer;
    command->opcode = COMPONENT_CMD_ATTEST;
    char id[50];
    sprintf(id,"%s",AP_secret_id);    
    char* hash=hashme256(&id);
    sprintf((char*)command->params,"%s",hash);
    free(hash);

    // Send out command and receive result
    int len = issue_cmd(addr, transmit_buffer, receive_buffer);
    if (len == ERROR_RETURN) {
	MXC_Delay(MXC_DELAY_MSEC(3000));
        print_error("Could not attest component\n");
        return ERROR_RETURN;
    }
    // decrypt attestation data
    attest_data* data=(attest_data*)receive_buffer;
    char* key=(char*)malloc(17);
    key=extract_key(KEY) ;
    char* hex_key=(char*)malloc(33);    
    hex_key=string_to_hex(key);
    uint8_t last_key[16];
    hex_string_to_bytes(hex_key,last_key);
    
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, last_key);
    arbitraryOperation();
    AES_ECB_decrypt(&ctx, data->loc);
    AES_ECB_decrypt(&ctx, data->date);
    AES_ECB_decrypt(&ctx, data->cust);
    arbitraryOperation();
    // Print out attestation data 
    print_info("C>0x%08x\n", component_id);
    char receive[MAX_I2C_MESSAGE_LEN];
    sprintf((char*)receive, "LOC>%s\nDATE>%s\nCUST>%s\n", data->loc, data->date, data->cust) + 1;
    print_info("%s", receive);
    free(key);
    free(hex_key);
    return SUCCESS_RETURN;
}
/********************************* AP LOGIC ***********************************/

// Boot sequence
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
    // POST BOOT FUNCTIONALITY
    #ifdef POST_BOOT
       POST_BOOT
    #else
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


// Function to validate the AP_PIN
int validate_pin() {
    size_t size=7;
    char buf[50];
    recv_input("Enter pin: ", buf,size);
    strcat(buf,pin_salt);
    char* hash = hashme256(buf);
    if (!secure_compare(hash, pin,65)) {
	free(hash);
        return SUCCESS_RETURN;
    }
    free(hash);
    MXC_Delay(MXC_DELAY_MSEC(3000));
    print_error("Invalid PIN!");
    return ERROR_RETURN;
}
// Function to validate the replacement token
int validate_token() {
    size_t size=17;
    char buf[50];
    recv_input("Enter token: ", buf,size);
    strcat(buf,token_salt);
    char* hash = hashme256(buf);
    if (!secure_compare(hash, token,65)) {
	 free(hash);
        return SUCCESS_RETURN;
    }
    free(hash);
    MXC_Delay(MXC_DELAY_MSEC(4500));
    print_error("Invalid token!");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    // Refuse duplicated components IDs
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
    if (flash_status.component_ids[i] == flash_status.component_ids[i+1]){ 
    MXC_Delay(MXC_DELAY_MSEC(100));
    print_error("ID's conflicted, can't proceed!!!");  
    return;     }}
    if (sign_components()) {
        print_error("Components could not be signed !!!\n");
        return;
    }
    if (boot_components()) {
        print_error("Failed to boot all components\n");
        return;
    }

    // Print boot message
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace() {
    size_t size=50;
    char buf[size];
    if (validate_token()) {
        print_error("invalid_TOKEN!!!");
        return ERROR_RETURN;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf,size);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf,size);
    sscanf(buf, "%x", &component_id_out);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",component_id_out);
}

// Attest a component if the PIN is correct
void attempt_attest() {
    // Refuse duplicated components IDs
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
    if (flash_status.component_ids[i] == flash_status.component_ids[i+1]){ 
    MXC_Delay(MXC_DELAY_MSEC(100));
    print_error("ID's conflicted, can't proceed!!!");  
    return; }}
    size_t size=50;
    char buf[size];
    if (validate_pin()) {
    	print_error("invalid PIN!!!");
        return;
    }
    
    uint32_t component_id;
    recv_input("Component ID: ", buf,size);
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
    size_t size=100;
    char buf[size];
    
    while (1) {
        recv_input("Enter Command: ", buf,size);
        // Execute requested command
        if (!secure_compare(buf, "list",4)) {
            scan_components();
        } else if (!secure_compare(buf, "boot",4)) {
            attempt_boot();
        } else if (!secure_compare(buf, "replace",7)) {
            attempt_replace();
        } else if (!secure_compare(buf, "attest",6)) {
            attempt_attest();
        } else {
            MXC_Delay(MXC_DELAY_MSEC(3000));
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}
