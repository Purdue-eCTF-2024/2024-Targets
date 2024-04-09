#include "board.h" 
#include "i2c.h"
#include "icc.h"
#include "led.h"
#include "simple_i2c_controller.h"

#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/rsa.h>

#include "board_link.h"
#include "simple_flash.h"
#include "host_messaging.h"


#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#endif

#ifdef POST_BOOT
#include "mxc_delay.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
#include "cat.h"

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
//example
int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    return send_packet(address, len, buffer);
}

// int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    
//      // Encrypt the data using AES encryption
//      uint8_t*  encrypted_data[len+1];
//      encrypt_aes(buffer, encrypted_data);
     
//      // Send the encrypted data over I2C
//      int sent = send_packet(address, len, encrypted_data);
//      if (sent == ERROR_RETURN) {
//          print_error("Error sending data over I2C: %d\n", sent);
//      }
//      return sent;
// }
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
// //example
int secure_receive(i2c_addr_t address, uint8_t* buffer) {
    return poll_and_receive_packet(address, buffer);
}
// int secure_receive(i2c_addr_t address, uint8_t* buffer) {
    
//      // Receive the encrypted data over I2C
//      int received = poll_and_receive_packet(address, buffer);
//      if (received == ERROR_RETURN) {
//          print_error("Error receiving data over I2C: %d\n", received);
//          return ERROR_RETURN;
//      }

//      // Decrypt the data using the AES encryption algorithm
//      uint8_t* decrypted_data[received+1];
//      decrypt_aes(buffer, decrypted_data);
    

//      // Copy the decrypted data to the output buffer
//      memcpy(buffer, decrypted_data, received);
//      return received;
// }

// int auth_component( const char* signature, size_t signature_size) {
//     // Attempt to find the component in the flash status
//    uint32_t component_id;
//     int i;
//     for (i = 0; i < flash_status.component_cnt; i++) {
//         if (flash_status.component_ids[i] == component_id) {
//             break;
//         }
//     }

//     // If the component is not found, return an error
//     if (i == flash_status.component_cnt) {
//         return ERROR_RETURN;
//     }

//     // Load the public key
//     RsaKey public_key;
//     if (wolfSSL_i2d_RSAPublicKey("public.pem", &public_key) != SSL_SUCCESS) {
//         return ERROR_RETURN;
//     }

//     uint8_t* signature_data = read_binary_file(signature, &signature_size);
//     // Verify the signature of the component
//     int result = wolfSSL_RsaVerifySignature(&public_key, signature_size, (unsigned char*) &component_id, signature_data, signature_size, EVP_sha256());

//     // Free the public key
//     wolfSSL_FreeX509PublicKey(&public_key);

//     // If the signature is valid, return success
//     if (result == SSL_SUCCESS) {
//         return SUCCESS_RETURN;
//     }

//     // If the signature is invalid, return an error
//     return ERROR_RETURN;
//     free(signature_data);
// }
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

//get the hash in a string format
char* mont_hash_result(uint8_t* hash_result) {
    char* hash_str = malloc(41); // +1 pour le caractère nul de fin de chaîne
    for (int i = 5; i < 20; i++) {
        char hex[3];
        sprintf(hex, "%02x", hash_result[i]);
        strncat(hash_str, hex, 2);
    }
    return hash_str;
}

//hashing function
void hash_hsn(char *pin,unsigned char *hash_result) {
    wc_Sha sha;
    unsigned char digest[WC_SHA_DIGEST_SIZE];
    size_t pin_length = strlen(pin);
    wc_InitSha(&sha);
    wc_ShaUpdate(&sha, pin, pin_length);
    wc_ShaFinal(&sha, digest);
    // Copy the digest to the output hash_result
    memcpy(hash_result, digest, WC_SHA_DIGEST_SIZE);
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
        //int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
         
        //Success, device is present
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
        //int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }

        validate_message* validate = (validate_message*) receive_buffer;
        // Check that the result is correct
        if (validate->component_id != flash_status.component_ids[i]) {
            print_error("Component ID: 0x%x invalid\n", flash_status.component_ids[i]);
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
       //int len = issue_cmd(addr, transmit_buffer, receive_buffer);
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

int attest_component(uint32_t component_id) {
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

int validate_pin() {
    char buf[7];
    unsigned char pin[WC_SHA_DIGEST_SIZE];
    recv_input("Enter pin: ", buf, 7);
    hash_hsn(buf, pin);
    char* chsn = mont_hash_result(pin);
    //compare  AP_PIN hash with the one you have.
    if (!strcmp(chsn, AP_PIN)) {
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }
    else{
        print_error("Invalid PIN! Try again in 5s...!\n");
        MXC_Delay(5000000);
        return ERROR_RETURN;
    }  
}

//Function to validate the replacement token
int validate_token() {
    char buf[17];
    unsigned char token[WC_SHA_DIGEST_SIZE];
    recv_input("Enter token: ", buf, 17);
    hash_hsn(buf, token);
    char* chsn = mont_hash_result(token);
    //compare  AP_TOKEN hash with the one you have.
    if (!strcmp(chsn, AP_TOKEN)) {
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }
    else{
        print_error("Invalid Token! Try again in 5s...! \n");
        MXC_Delay(5000000);
        return ERROR_RETURN;
    }
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

// Replace a component if the token is correct
void attempt_replace() {
    char buf[11];

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf, 11);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf, 11);
    sscanf(buf, "%x", &component_id_out);
    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;
            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out, component_id_in);
            print_success("Replace\n");
            return;
        }
    }
    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",component_id_out);
}

 // Attest a component if the PIN is correct
void attempt_attest() {
    char buf[11];

    if (validate_pin()) {
        return;
    }

    uint32_t component_id;
    recv_input("Component ID: ", buf, 11);
    sscanf(buf, "%x", &component_id);
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id) {
            if (attest_component(component_id) == SUCCESS_RETURN) {
                print_success("Attest\n");
                }
         }
    }
    print_error("Component not provisioned\n");
}


/*********************************** MAIN *************************************/
typedef struct {
    const char *name;
    void (*function)();
} Command;

int main() {
    // Initialize board
    init();
    // Handle commands forever
    char buf[8];
    while (1)
    {
        Command commands[] = 
        {
            {"list", scan_components},
            {"boot", attempt_boot},
            {"replace", attempt_replace},
            {"attest", attempt_attest}
        };
        recv_input("Enter Command: ", buf, 8);

        // Remove newline character from input
        buf[strcspn(buf, "\n")] = '\0';

        // Execute requested command
        for (int i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
            {
                if (!strcmp(buf, commands[i].name)) 
                {
                    commands[i].function();
                    break;
                }
            }
    }

    // Code never reaches here
    return 0;
}
