/**
 * @file component.c
 * @author Jacob Doll
 * @editor ERA Team
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */
#include <stdint.h>
#include <stddef.h>
#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>


#include "simple_i2c_peripheral.h"
#include "board_link.h"

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"
#include "aes.h"
#define BLOCK_SIZE 64

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
    COMPONENT_CMD_SIGN
} component_cmd_t;

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for receiving messages from the AP
typedef struct {
	uint8_t loc[65];
	uint8_t date[65];
	uint8_t cust[65];
}attest_data;

typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

typedef struct {
    uint8_t authenticity[65];
    uint8_t message[65];
    uint8_t integrity[65];

    
}secure_message;

typedef struct {
    uint32_t component_id;
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(uint8_t* password);
void process_scan(void);
void process_validate(void);
void process_attest(void);
void process_sign(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];


/********************************** REQUIRED FUNCTIONS **********************************/

#define MAX_STRING_LENGTH 20

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

//alternative function of comparaison 
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
//function to transform string to hex
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
// function to transform hex string to integer
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

//function to extract 16bytes key from a random lenght string
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


/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
*/

void secure_send(uint8_t* buffer, uint8_t len) {
    //copying buffer
    uint8_t buffer_copy1[MAX_I2C_MESSAGE_LEN-1];
    uint8_t buffer_copy2[MAX_I2C_MESSAGE_LEN-1];
    memcpy(&buffer_copy1,buffer,len);
    memcpy(&buffer_copy2,buffer,len);
	
    secure_message* secure=(secure_message*) buffer_copy1;
    
    //authenticity
    char comp_buf[65];
    sprintf(comp_buf,"%s%x%s",COMP_secret_id,COMPONENT_ID,AP_secret_id);
    char* comp_hash=hashme256(&comp_buf);
    sprintf((char*)secure->authenticity,"%s",comp_hash);
    secure->authenticity[64]='\0';
    free(comp_hash);
    
    //integrity
    memcpy(&secure->message,buffer,len);    
    char integ[64];
    sprintf(integ,"%i%s",*buffer_copy2,SECRET_messaging);
    char* integ_hash=hashme256(&integ);
    sprintf(secure->integrity,"%s",integ_hash);
    secure->integrity[64]='\0';
    free(integ_hash);
	
    //sending packet
    send_packet_and_ack(MAX_I2C_MESSAGE_LEN-1, buffer_copy1);
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
*/
int secure_receive(uint8_t* buffer) {
    //receiving
    int ret=wait_and_receive_packet(receive_buffer);
	
    //casting message form
    secure_message* secure=(secure_message*) receive_buffer;    
    
    //authenticity test
    char ap_buf[65];
    sprintf(ap_buf,"%s%x%s",AP_secret_id,COMPONENT_ID,COMP_secret_id);
    char* ap_hash=hashme256(&ap_buf);
    if(secure_compare(ap_hash,(char*)secure->authenticity,65)){
    	MXC_Delay(MXC_DELAY_MSEC(3000));
    	free(buffer);
	free(ap_hash);
    	return ERROR_RETURN;
    }
    //integrity test
    char integ[65];
    sprintf(integ,"%i%s",*secure->message,SECRET_messaging);
    char* integ_hash=hashme256(&integ);
    if(secure_compare(integ_hash,(char*)secure->integrity,65)){
	free(integ_hash);
	MXC_Delay(MXC_DELAY_MSEC(3000));
    	free(buffer);
    	return ERROR_RETURN;
    }
    free(integ_hash);
    //extracting message
    memcpy(buffer,secure->message,65);

        return ret;
}


/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
void boot() {

    // POST BOOT FUNCTIONALITY
    #ifdef POST_BOOT
    POST_BOOT
    #else
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
        process_boot(command->params);
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
    case COMPONENT_CMD_SIGN:
        process_sign();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        MXC_Delay(MXC_DELAY_MSEC(4500));
        break;
    }
}

void process_boot(uint8_t* password) {
    // The AP requested a boot. component verifies its validity
    char id[50];
    sprintf(id,"%s",AP_secret_id);
    char* hash=hashme256(&id);
    //comparing AP_credentials to the stored ones
    if (!secure_compare((char*)password,hash,32)){
	free(hash);
    	uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    	memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
    // component respond with the boot message
        send_packet_and_ack(len, transmit_buffer);
    // Call the boot function
        boot();
    }
    return;
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
    //preparing attestation data
    attest_data* data=(attest_data*) transmit_buffer;
    data->loc[64]='\0';
    data->date[64]='\0';
    data->cust[64]='\0';

    //converting data to bytes
    hex_string_to_bytes(ATTESTATION_LOC, data->loc);
    hex_string_to_bytes(ATTESTATION_DATE, data->date);
    hex_string_to_bytes(ATTESTATION_CUSTOMER, data->cust);
    //sending attestation data            
    send_packet_and_ack(MAX_I2C_MESSAGE_LEN-1, transmit_buffer);
}


void process_sign() {
    // The AP requested signature. component respond with a known hash value
    //creation of component identifier
    char id[50];
    sprintf(id,"%x",COMPONENT_ID);
    strcat(id,COMP_secret_id);
    char* hash=hashme256(&id);
    uint8_t len = sprintf((char*)transmit_buffer,"%s",hash) + 1;
    free(hash);
    //sending signarure
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
    char id[50];
    sprintf(id,"%s",AP_secret_id);
    char* hash=hashme256(&id);

    while (1) {
        wait_and_receive_packet(receive_buffer);
        command_message* command0 = (command_message*) receive_buffer;
        
        //check credentials: we use this operation to prevent any external AP from usig our components
    if (!secure_compare((char*)command0->params,hash,65)){
        component_process_cmd();
        }
      else{free(hash); MXC_Delay(MXC_DELAY_MSEC(3000));}  
    }
}
