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
#include "i2s.h"
#include "cameraif.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"
#include "trng.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "board_link.h"
#include "simple_flash.h"
#include "host_messaging.h"

#include "wolfssl/wolfssl/ssl.h"
#include "wolfssl_rxtx.h"
#include "rng.h"

#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
#include "secrets_ap.h"

/********************************* CONSTANTS **********************************/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

// Buffer sizes
#define BUFFER_CMD_SIZE 20
#define BUFFER_HASH_SIZE 64
#define BUFFER_PIN_SIZE 6
#define BUFFER_TOKEN_SIZE 16
#define BUFFER_CMPID_SIZE 10
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

int __attribute__((noinline, optimize(0))) secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    if (get_random_trng() == ERROR_RETURN){
        return ERROR_RETURN;
    }
    int ret = 0;
    int err = 0;
    uint8_t snd_len[1] = {len};

    // Ensure I2C register flags have expected value.
    // Sometimes these are not set properly
    i2c_simple_write_receive_len(address, 0);
    i2c_simple_write_transmit_len(address, 0);

    // Init wolfSSL library
    // Technically we should do this once, but
    // we want to ensure every invocation of wolfSSL
    // is a fresh state
    wolfSSL_Init();

    tls13_buf *tbuf; 
    WOLFSSL_CTX *ctx; 
    WOLFSSL *ssl; 
    do {
        tbuf = ssl_new_buf(address);
        ctx = ssl_new_context_client();
        ssl = ssl_new_session(ctx, tbuf);
        // Need to delay the AP to ensure the component is 
        // in its loop before proceeding
        MXC_Delay(5000);
        ret = ssl_handshake_client(ssl, tbuf);
    } while (ret == -1);

    // Send length of data to transmit via wolfSSL
    do {
        // Need to delay the AP to ensure the component is 
        // in its loop before proceeding
        MXC_Delay(5000);
        ret = wolfSSL_write(ssl, snd_len, 1);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);

    // Error, free all memory
    if (ret <= 0) {
        ssl_free_all(ctx, ssl, tbuf);
        return ERROR_RETURN;
    }

    // Send data via wolfSSL
    do {
        // Need to delay the AP to ensure the component is 
        // in its loop before proceeding
        MXC_Delay(5000);
        ret = wolfSSL_write(ssl, buffer, len);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);

    // Error, free all memory
    if (ret <= 0) {
        ssl_free_all(ctx, ssl, tbuf);
        return ERROR_RETURN;
    }

    // Free all memory
    ssl_free_all(ctx, ssl, tbuf);
    wolfSSL_Cleanup();

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
 * This function must be implemented by your team to align with the security requirements.
*/
int __attribute__((noinline, optimize(0))) secure_receive(i2c_addr_t address, uint8_t* buffer) {
    if (get_random_trng() == ERROR_RETURN){
        return ERROR_RETURN;
    }
    int ret = 0;
    int err = 0;
    uint8_t rcv_len[1] = {0};

    // Ensure I2C register flags have expected value.
    // Sometimes these are not set properly
    i2c_simple_write_receive_len(address, 0);
    i2c_simple_write_transmit_len(address, 0);

    // Init wolfSSL library
    // Technically we should do this once, but
    // we want to ensure every invocation of wolfSSL
    // is a fresh state
    wolfSSL_Init();

    tls13_buf *tbuf; 
    WOLFSSL_CTX *ctx; 
    WOLFSSL *ssl; 
    do {
        tbuf = ssl_new_buf(address);
        ctx = ssl_new_context_client();
        ssl = ssl_new_session(ctx, tbuf);
        // Need to delay the AP to ensure the component is 
        // in its loop before proceeding
        MXC_Delay(5000);
        ret = ssl_handshake_client(ssl, tbuf);
    } while (ret == -1);

    // Get length of data being transmitted via wolfSSL
    do {
        // Need to delay the AP to ensure the component is 
        // in its loop before proceeding
        MXC_Delay(5000);
        ret = wolfSSL_read(ssl, rcv_len, 1);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);

    // Error, free all memory
    if (ret <= 0) {
        ssl_free_all(ctx, ssl, tbuf);
        return ERROR_RETURN;
    }

    uint8_t t_len = rcv_len[0];

    // Receive data via wolfSSL
    do {
        // Need to delay the AP to ensure the component is 
        // in its loop before proceeding
        MXC_Delay(5000);
        ret = wolfSSL_read(ssl, buffer, t_len);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);

    // Error, free all memory
    if (ret <= 0) {
        ssl_free_all(ctx, ssl, tbuf);
        return ERROR_RETURN;
    }

    // Free all memory
    ssl_free_all(ctx, ssl, tbuf);
    wolfSSL_Cleanup();

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

    // Initialize the TRNG hardware
    MXC_TRNG_Init();

    // Disable the audio jacks
    MXC_I2S_TXDisable();
    MXC_I2S_RXDisable();

    // Disable camera
    MXC_PCIF_Stop();
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive) {
    // Send message
    int result = secure_send(addr, transmit, sizeof(uint8_t));
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    
    // Receive message
    int len = secure_receive(addr, receive);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    return len;
}

/**
 * @brief Issues a wake command to the component
 * 
 * @param i2c_addr_t addr: The address of the component to wake up
 * 
 * @return int: Number of bytes received from the component
*/
int issue_wake(i2c_addr_t addr) {
    // Send message
    uint8_t transmit[1] = {0x11};
    uint8_t receive[1] = {0};

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
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN] = {0};

    // Scan scan command to each component 
    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // I2C Blacklist:
        // 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }
        
        // check if device is present
        int len = issue_wake(addr);

        // Success, device is present
        if (len > 0) {

            // Create command message 
            command_message* command = (command_message*) transmit_buffer;
            command->opcode = COMPONENT_CMD_SCAN;

            // Send out command and receive result
            int res = issue_cmd(addr, transmit_buffer, receive_buffer);

            // Success, device is present
            if (res > 0) {
                scan_message* scan = (scan_message*) receive_buffer;
                print_info("F>0x%08x\n", scan->component_id);
            }
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
        // command->opcode = COMPONENT_CMD_VALIDATE;
        command->opcode = COMPONENT_CMD_BOOT;


        int len = issue_wake(addr);

        if (len > 0) {    
        
            // Send out command and receive result
            int res = issue_cmd(addr, transmit_buffer, receive_buffer);
            if (res == ERROR_RETURN) {
                print_error("Could not validate component\n");
                return ERROR_RETURN;
            }

            validate_message* validate = (validate_message*) receive_buffer;
            // Check that the result is correct
            if (validate->component_id != flash_status.component_ids[i]) {
                print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
                return ERROR_RETURN;
            }
        } else return ERROR_RETURN;
    }
    return SUCCESS_RETURN;
}

int boot_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // Create command message
        
        // Send out command and receive result
        // int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        int len = secure_receive(addr, receive_buffer);
        if (len == ERROR_RETURN) {
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

    int len = issue_wake(addr);

    if (len > 0) {
        // Send out command and receive result
        int res = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (res == ERROR_RETURN) {
            print_error("Could not attest component\n");
            return ERROR_RETURN;
        }

        // Print out attestation data 
        print_info("C>0x%08x\n", component_id);
        print_info("%s", receive_buffer);
        return SUCCESS_RETURN;
    }

    print_error("Could not attest component\n");
    return ERROR_RETURN;
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
int validate_pin(char *buf) {
    char hash[BUFFER_HASH_SIZE] = {0};

    int res = recv_input("Enter pin: ", buf, BUFFER_PIN_SIZE);
    if (res != SUCCESS_RETURN)
        return ERROR_RETURN;

    if (sha512(buf, BUFFER_PIN_SIZE, hash)){
        print_error("Invalid PIN!\n");
        XMEMSET(buf, 0, BUFFER_PIN_SIZE);
        return ERROR_RETURN;
    }

    const char pin_string[] = AP_PIN; 
    const char *pos = pin_string;
    unsigned char ap_pin[BUFFER_HASH_SIZE];
    
    for (size_t count = 0; count < BUFFER_HASH_SIZE; count++) {
        sscanf(pos, "%2hhx", &ap_pin[count]);
        pos += 2;
    }

    if (!XSTRNCMP(hash, ap_pin, BUFFER_HASH_SIZE)) {
        print_debug("Pin Accepted!\n");
        XMEMSET(buf, 0, BUFFER_PIN_SIZE);
        return SUCCESS_RETURN;
    }
    print_error("Invalid PIN!\n");
    XMEMSET(buf, 0, BUFFER_PIN_SIZE);
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token(char *buf) {
    char hash[BUFFER_HASH_SIZE] = {0};
    int res = recv_input("Enter token: ", buf, BUFFER_TOKEN_SIZE);
    if (res != SUCCESS_RETURN)
        return ERROR_RETURN;
        
    if (sha512(buf, BUFFER_TOKEN_SIZE, hash)){
        print_error("Invalid PIN!\n");
        XMEMSET(buf, 0, BUFFER_PIN_SIZE);
        return ERROR_RETURN;
    }

    const char token_string[] = AP_TOKEN; 
    const char *pos = token_string;
    unsigned char ap_token[BUFFER_HASH_SIZE];

    for (size_t count = 0; count < BUFFER_HASH_SIZE; count++) {
        sscanf(pos, "%2hhx", &ap_token[count]);
        pos += 2;
    }

    if (!XSTRNCMP(hash, ap_token, BUFFER_HASH_SIZE)) {
        print_debug("Token Accepted!\n");
        XMEMSET(buf, 0, BUFFER_TOKEN_SIZE);
        return SUCCESS_RETURN;
    }
    print_error("Invalid Token!\n");
    XMEMSET(buf, 0, BUFFER_TOKEN_SIZE);
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
void attempt_replace(char* buf) {

    if (validate_token(buf)) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;
    
    recv_input("Component ID In: ", buf, BUFFER_CMPID_SIZE);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf, BUFFER_CMPID_SIZE);
    sscanf(buf, "%x", &component_id_out);

    if (component_id_in == component_id_out) {
        print_error("Component 0x%08x is already provisioned for the system\r\n",
                component_id_out);
        return;
    }

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
void attempt_attest(char *buf) {
    if (validate_pin(buf)) {
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", buf, BUFFER_CMPID_SIZE);
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

/*********************************** MAIN *************************************/

int main() {
    // Initialize board
    init();

    // Increase clock speed to 100 MHz (Hopefully :))
    MXC_SYS_Clock_Select(MXC_SYS_CLOCK_IPO);
    
    #ifdef CRYPTO_EXAMPLE
        print_debug("CRYPTO_EXAMPLE enabled");
    #endif

    // Print the component IDs to be helpful
    // Your design does not need to do thisand th
    print_info("Application Processor Started\n");

    // Handle commands forever
    char cmd_buf[BUFFER_CMD_SIZE + 1] = {0};
    char pin_buf[BUFFER_PIN_SIZE + 1] = {0};
    char token_buf[BUFFER_TOKEN_SIZE + 1] = {0};
    
    while (1) {
        XMEMSET(cmd_buf, 0, BUFFER_CMD_SIZE + 1);
        XMEMSET(pin_buf, 0, BUFFER_PIN_SIZE + 1);
        XMEMSET(token_buf, 0, BUFFER_TOKEN_SIZE + 1);

        recv_input("Enter Command: ", cmd_buf, BUFFER_CMD_SIZE);

        // Execute requested command
        if (!XSTRNCMP(cmd_buf, "list", sizeof cmd_buf)) {
            scan_components();
        } else if (!XSTRNCMP(cmd_buf, "boot", sizeof cmd_buf)) {
            attempt_boot();
        } else if (!XSTRNCMP(cmd_buf, "replace", sizeof cmd_buf)) {
            attempt_replace(token_buf);
        } else if (!XSTRNCMP(cmd_buf, "attest", sizeof cmd_buf)) {
            attempt_attest(pin_buf);
        } else {
            print_error("Unrecognized command '%s'\n", cmd_buf);
        }
    }

    // Code never reaches here
    return 0;

}
