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
#include "rtc.h"
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

#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#endif

#include "simple_crypto.h"
#include "security.h"

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"
/********************************* CONSTANTS **********************************/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

// Bruteforce protection
#define TIMEOUT_SECONDS 4

// Pepper length
#define PEPPER_LEN strlen(HASH_PEPPER)
#define PIN_LEN 6
#define TOKEN_LEN 16

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. This is not utilized by the example
// design but can be utilized by your design.
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
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;

// Timer for bruteforce protection
bool timer_active = false;
uint32_t start_time = 0;

// "In the echo of memory, the reference flag once proudly flew, but now, 
// its absence casts a shadow of loss, a silent testament to what once was."

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
int secure_send(i2c_addr_t address, uint8_t* buffer, uint8_t len) {
    // Create a buffer to hold the encrypted packet
    size_t encrypted_len = len + 1 + IV_SIZE + TAG_SIZE;

    // Allocate memory for the encrypted packet
    uint8_t encrypted_packet[encrypted_len];

    if (create_encrypted_packet(buffer, len, ENCRYPTION_KEY, encrypted_packet) != 0) {
        // Something failed, return error
        return ERROR_RETURN;
    }

    // Send the encrypted packet
    return send_packet(address, encrypted_len, encrypted_packet);
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

    // Wait for a packet to be received
    poll_and_receive_packet(address, buffer);

    // Create a buffer to hold the decrypted packet
    size_t decrypted_len = buffer[0] - 1 - IV_SIZE - TAG_SIZE;

    // Allocate memory for the decrypted packet
    uint8_t decrypted_packet[decrypted_len];

    if (decrypt_encrypted_packet(buffer, ENCRYPTION_KEY, decrypted_packet) != 0) {
        // Something failed, return error
        return ERROR_RETURN;
    }

    // Copy the decrypted packet into the buffer
    memcpy(buffer, decrypted_packet, decrypted_len);

    // Return the length of the decrypted packet
    return decrypted_len;
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

/**
 * @brief Start Timer for Bruteforce Protection
*/
void start_timer() {
    timer_active = true;
    start_time = MXC_RTC_GetSecond();
}

/**
 * @brief Check if Timer has Expired
 * 
 * @return bool: true if timer has expired, false otherwise
*/
bool timer_expired() {

    // If the timer is not active, then it has expired
    if (!timer_active) {
        return true;
    }

    uint32_t current_time = MXC_RTC_GetSecond();

    // If the timer is active and 4 seconds have passed, then timer has expired
    if (timer_active && (current_time - start_time) >= TIMEOUT_SECONDS) {
        timer_active = false;
        return true;
    }

    // Timer is still active
    return false;
}

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

    // Setup real time clock
    if (MXC_RTC_Init(0, 0) != E_NO_ERROR) {
        print_error("RTC init failed\n");
        while (1) {}
    }

    if (MXC_RTC_Start() != E_NO_ERROR) {
        print_error("RTC start failed\n");
        while (1) {}
    }

    // Initialize board link interface
    board_link_init();
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive) {
    // Send message

    // Create a new transmit buffer to also attach the AP token to
    uint8_t buffer_size = 1 + strlen(AP_FIRMWARE_TOKEN) + 1;
    uint8_t buffer[buffer_size];
    
    // Copy current transmit buffer into buffer (just the opcode)
    memcpy(buffer, transmit, 1); // Copy the opcode into the buffer
    strcpy((char*)buffer + 1, AP_FIRMWARE_TOKEN); // Copy the AP token into the buffer (including null terminator)

    // Send modified packet
    int result = send_packet(addr, buffer_size, buffer);
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
        transmit_buffer[0] = COMPONENT_CMD_SCAN;
        
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
        transmit_buffer[0] = COMPONENT_CMD_VALIDATE;
        
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

    int matches = 0;

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // Create command message
        transmit_buffer[0] = COMPONENT_CMD_BOOT;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        char *component_token = (char*)receive_buffer; // First part of the message is the component token
        char *component_boot_msg = (char*)receive_buffer + strlen(COMPONENT_FIRMWARE_TOKEN) + 1; // Rest of the message is the boot message

        // Compare received component token with COMPONENT_FIRMWARE_TOKEN
        if (!constant_strcmp(component_token, COMPONENT_FIRMWARE_TOKEN)) {
            print_error("Component 0x%08x token invalid\n", flash_status.component_ids[i]);
            return ERROR_RETURN;
        }

        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i], component_boot_msg);
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
    transmit_buffer[0] = COMPONENT_CMD_ATTEST;

    // Send out command and receive result
    int len = issue_cmd(addr, transmit_buffer, receive_buffer);
    if (len == ERROR_RETURN) {
        print_error("Could not attest component\n");
        return ERROR_RETURN;
    }

    // Print out attestation data 
    print_info("C>0x%08x\n", component_id);
    print_info("%s", receive_buffer);
    return SUCCESS_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
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

// Compare the entered PIN to the correct PIN
int validate_pin() {
    char buf[50];
    recv_input("Enter pin: ", buf, 50);

    if (strlen(buf) != PIN_LEN) {
        print_error("Invalid PIN!\n");
        return ERROR_RETURN;
    }

    // 1. Get the entered PIN (excluding the null terminator)
    // 2. Concatenate the entered PIN with HASH_PEPPER
    // 3. Hash the result using SHA256
    // 4. Compare the result to AP_PIN

    char pin[PIN_LEN + PEPPER_LEN];
    memcpy(pin, buf, PIN_LEN);
    memcpy(pin + PIN_LEN, HASH_PEPPER, PEPPER_LEN);
    uint8_t hash_out[HASH_SIZE];
    sha256_hash(pin, PIN_LEN + PEPPER_LEN, hash_out);

    char hash_str[HASH_SIZE * 2 + 1];
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hash_str + i * 2, "%02x", hash_out[i]);
    }

    hash_str[HASH_SIZE * 2] = '\0';

    if (constant_strcmp(hash_str, AP_PIN)) {
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }

    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() {
    char buf[50];
    recv_input("Enter token: ", buf, 50);

    // Check to make sure the token is the correct length
    if (strlen(buf) != TOKEN_LEN) {
        print_error("Invalid Token!\n");
        return ERROR_RETURN;
    }

    // 1. Get the entered token (excluding the null terminator)
    // 2. Concatenate the entered token with HASH_PEPPER
    // 3. Hash the result using SHA256
    // 4. Compare the result to AP_TOKEN

    char token[TOKEN_LEN + PEPPER_LEN];
    memcpy(token, buf, TOKEN_LEN);
    memcpy(token + TOKEN_LEN, HASH_PEPPER, PEPPER_LEN);
    uint8_t hash_out[HASH_SIZE];
    sha256_hash(token, TOKEN_LEN + PEPPER_LEN, hash_out);

    // Convert hash to string
    char hash_str[HASH_SIZE * 2 + 1];
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hash_str + i * 2, "%02x", hash_out[i]);
    }
    hash_str[HASH_SIZE * 2] = '\0';

    if (constant_strcmp(hash_str, AP_TOKEN)) {
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

    // "Like a fading star in the vast expanse of night, the reference flag once 
    // illuminated our path with its presence, but now, its absence leaves us wandering 
    // in the darkness of longing."

    // uint8_t *plaintext = "This is a test.";
    // uint8_t packet[256];

    // // Create an encrypted packet
    // if (create_encrypted_packet(plaintext, strlen(plaintext), ENCRYPTION_KEY, packet) != 0) {
    //     print_error("Failed to create encrypted packet\n");
    //     return;
    // }

    // // print the encrypted packet
    // print_debug("Encrypted Packet: ");
    // for (int i = 0; i < 1 + IV_SIZE + TAG_SIZE + strlen(plaintext); i++) {
    //     print_debug("%02x", packet[i]);
    // }

    // print_debug("\n");

    // // Decrypt the encrypted packet
    // int plaintext_len = packet[0] - 1 - IV_SIZE - TAG_SIZE;
    // uint8_t decrypted[plaintext_len];
    // if (decrypt_encrypted_packet(packet, ENCRYPTION_KEY, decrypted) != 0) {
    //     print_error("Failed to decrypt encrypted packet\n");
    //     return;
    // }

    // // print the decrypted packet
    // print_debug("Decrypted Packet: %s\n", decrypted);

    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace() {

    // If timer has not expired, print error and return
    if (!timer_expired()) {
        print_error("You must wait 4 seconds between failed replace attempts\n");
        return;
    }

    char buf[50];

    if (validate_token()) {
        start_timer(); // Invalid token, start timer
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf, 50);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf, 50);
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
void attempt_attest() {

    // If timer has not expired, print error and return
    if (!timer_expired()) {
        print_error("You must wait 4 seconds between failed attestation attempts\n");
        return;
    }

    char buf[50];

    if (validate_pin()) {
        start_timer(); // Invalid pin, start timer
        return;
    }

    uint32_t component_id;
    recv_input("Component ID: ", buf, 50);
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
    // print_info("Provisioned Component IDs: ");
    // for (unsigned i = 0; i < flash_status.component_cnt; i++) {
    //     print_info("0x%08x ", flash_status.component_ids[i]);
    // }

    // Make sure connected components are legitimate and not counterfeit
    // If any provisioned components are missing or counterfeit, the AP will not accept any pre-boot commands
    // if (validate_components()) {
    //     print_error("Components could not be validated. Halting AP.\n");
    //     return ERROR_RETURN;
    // }

    // Handle commands forever
    char buf[100];
    while (1) {

        recv_input("Enter Command: ", buf, 100);

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
