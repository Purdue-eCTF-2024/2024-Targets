/**
 * @file application_processor.c
 * @author Kevin Marquis
 * @brief eCTF AP UConn Design Implementation
 * @date 2024
 *
 * @note Based on the example code provided in application_processor.c by Jacob Doll. Copyright (c) 2024 The MITRE Corporation
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

//Cryptography Headers
#include "certs.h"

#include "simple_trng.h"
#include "handshake.h"
#include "wolfssl/wolfssl/options.h"
#include "wolfssl/wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/aes.h"

#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#endif

// Includes from containerized build
#include "ectf_params.h"

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define AP_PIN "123456"
#define AP_TOKEN "0123456789abcdef"
#define COMPONENT_IDS 0x11111124, 0x11111125
#define COMPONENT_CNT 2
#define AP_BOOT_MSG "Test boot message"
*/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

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

typedef struct {
    i2c_addr_t addr;
    tls_key handshake_ctx;
    Aes enc;
    Aes dec;
    int msg_count;
} post_boot_io;

// Datatype for commands sent to components
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/********************************* GLOBAL VARIABLES **********************************/
flash_entry flash_status; // Variable for information stored in flash memory
post_boot_io dev_connections[COMPONENT_CNT];

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
    int i = 0;
    uint8_t OUT_BUF[255] = {0};
    int full_len = len + sizeof(int);
    for (; i < COMPONENT_CNT; i++){
        if (dev_connections[i].addr == address){
            break;
        }
    }

    printf("Here\n");
    if (len < (255 - sizeof(int))){
        memcpy(OUT_BUF, &(dev_connections[i].msg_count), sizeof(int));
        memcpy(OUT_BUF + sizeof(int), buffer, len);
    }
    else{
        return -1;
    }
    
    dev_connections[i].msg_count += 1;
    return secure_send_lite(address, &(dev_connections[i].enc), &(dev_connections[i].handshake_ctx), OUT_BUF, full_len);
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
    int i = 0;
    int ret;
    uint8_t IN_BUF[255] = {0};
    for (; i < COMPONENT_CNT; i++){
        if (dev_connections[i].addr == address){
            break;
        }
    }

    ret = secure_receive_lite(address, &(dev_connections[i].dec), &(dev_connections[i].handshake_ctx), IN_BUF, 255);
    if (((int *)IN_BUF)[0] != dev_connections[i].msg_count){
        return -1;
    }
    dev_connections[i].msg_count+=1;
    ret -= sizeof(int);
    memcpy(buffer, IN_BUF + sizeof(int), ret);

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
    #if DEBUG
    print_debug("Successfully sent command\n");
    #endif
    
    // Receive message
    int len = poll_and_receive_packet(addr, receive);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    #if DEBUG
    print_debug("Successfully received command acknowledgement.\n");
    #endif
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
    int ret;

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
    int ret;
    uint8_t iv[16] = {0};

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

        tls_key boot_ctx;

        ret = handshake_lite(addr, &(dev_connections[i].handshake_ctx));
        if (ret != 0){
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        ret = wc_AesInit(&(dev_connections[i].dec), NULL, INVALID_DEVID);
        if (ret != 0) {
            // failed to initialize aes key
            print_error("Failed to initialize decryption key.\n");
            return ERROR_RETURN;
        }

        ret = wc_AesSetKey(&(dev_connections[i].dec), dev_connections[i].handshake_ctx.key, dev_connections[i].handshake_ctx.key_len, iv, AES_DECRYPTION);
        if (ret != 0) {
            print_error("Failed to initialize decryption key.\n");
            return ERROR_RETURN;
        }

        for (int i = 0; i < 16; i++){
            iv[i] = 0;
        }

        ret = wc_AesInit(&(dev_connections[i].enc), NULL, INVALID_DEVID);
        if (ret != 0) {
            // failed to initialize aes key
            print_error("Failed to initialize encryption key.\n");
            return ERROR_RETURN;
        }

        ret = wc_AesSetKey(&(dev_connections[i].enc), dev_connections[i].handshake_ctx.key, dev_connections[i].handshake_ctx.key_len, iv, AES_ENCRYPTION);
        if(ret != 0) {
        // failed to set aes key
            print_error("Failed to initialize encryption key.\n");
            return ERROR_RETURN;
        }

        for (int i = 0; i < MAX_I2C_MESSAGE_LEN; i++){
            receive_buffer[i] = 0;
        }

        dev_connections[i].addr = addr;
        dev_connections[i].msg_count = 0;

        ret = secure_receive_lite(addr, &(dev_connections[i].dec), &(dev_connections[i].handshake_ctx), receive_buffer, 255);
        if (ret < 0){
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
    uint8_t iv[16] = {0};
    tls_key attest_ctx;
    int ret;
    Aes aes_ctx;

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Create command message
    command_message* command = (command_message*) transmit_buffer;
    command->opcode = COMPONENT_CMD_ATTEST;

    // Send out command and receive result
    int len = issue_cmd(addr, transmit_buffer, receive_buffer);
    if (len == ERROR_RETURN) {
        print_error("Failed to issue attest command\n");
        return ERROR_RETURN;
    }

    //Validate component via handshake
    ret = handshake_lite(component_id, &attest_ctx);
    if (ret != 0){
        print_error("Failed to complete handshake.\n");
        return ERROR_RETURN;
    }

    ret = wc_AesInit(&aes_ctx, NULL, INVALID_DEVID);
    if (ret != 0) {
        // failed to initialize aes key
        print_error("Failed to initialize encryption key.  Returned %d\n", ret);
    }

    ret = wc_AesSetKey(&aes_ctx, attest_ctx.key, attest_ctx.key_len, iv, AES_DECRYPTION);
    if (ret != 0) {
    // failed to set aes key
        print_error("Failed to set decryption key.  Returned %d\n", ret);
    }

    //Receive Data
    ret = secure_receive_lite(component_id, &aes_ctx, &attest_ctx, receive_buffer, MAX_I2C_MESSAGE_LEN);
    if (ret < 0){
        print_error("Failed to receive attestation data.\n");
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
    char pin[] = AP_PIN;

    recv_input("Enter pin: ", buf);

    if (!double_hmac_cmp(pin, buf, strlen(pin), strlen(buf))){
        print_debug("PIN Accepted!\n");
        return SUCCESS_RETURN;
    }

    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() {
    char buf[50];
    char token[] = AP_TOKEN;

    recv_input("Enter token: ", buf);

    if (!double_hmac_cmp(token, buf, strlen(token), strlen(buf))){
        print_debug("Token Accepted!\n");;
        return SUCCESS_RETURN;
    }
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
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
    char buf[50];
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN] = {0};
    i2c_addr_t target_addr;
    int ret;
    tls_key replace_ctx;

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf);
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

int main() {
    // Initialize board
    init();
    int ret = MXC_TRNG_Init();
    if (ret){
        print_error("TRNG Failed to initialize!\n");
    }
    ret = MXC_AES_Init();
    if (ret != E_SUCCESS){
        print_error("Failed to turn on AES Unit\n");
    }

    print_info("Application Processor Started\n");

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
