#include "board.h"
#include "ectf_params.h"
#include "i2c.h"
#include "icc.h"
#include "led.h"
#include "mxc_delay.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Includes from containerized build
#include "ectf_params.h"
#include "ectf_params_encrypted.h"
#include "global_secrets.h"

// Custom Packages
#include "boardlink_ap.h"
#include "helper_functions.h"
#include "secure_ap.h"
#include "secure_buffer.h"
#include "secure_host_messaging.h"
#include "simple_flash.h"

// Crypto Library
#include "crypto_wolfssl.h"
#include "wolfssl/wolfcrypt/hash.h"

#ifdef POST_BOOT
#include "mxc_delay.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

#if COMPONENT_CNT > 32
#error Too many components!!
#endif

// For sending commands make the opcode as first element of buffer

flash_entry_ap_t flash_status;
INIT_BUF_U8(verified, COMPONENT_CNT);
crypto_config crypto[COMPONENT_CNT];

// Buffers for board link communication
INIT_BUF_U8(receive_buffer, MAX_I2C_MESSAGE_LEN);
INIT_BUF_U8(transmit_buffer, MAX_I2C_MESSAGE_LEN);

uint8_t key_buf[] = {MASTER_KEY};
buf_u8 master_key = {.data = key_buf, .size = KEY_LEN_BYTES * MASTER_KEY_COUNT};

// POST BOOT FUNCTIONS
int secure_send(uint8_t address, uint8_t *buffer, uint8_t len) {
    // set_state(1);
    cpyin_raw_bu8(transmit_buffer, buffer, len);
    crypto_config *dest_config = NULL;
    for (uint32_t i = 0; i < flash_status.component_cnt; i++) {
        if (address == component_id_to_i2c_addr(crypto[i].component_id)) {
            dest_config = &crypto[i];
            break;
        }
    }
    if (dest_config == NULL)
        panic();

    int result = ap_send(slice_bu8(transmit_buffer, 0, len), dest_config);
    if (result != SUCCESS_RETURN)
        panic();
    // set_state(0);
    return result;
}

int secure_receive(i2c_addr_t address, uint8_t *buffer) {
    // set_state(1);
    crypto_config *dest_config = NULL;
    for (uint32_t i = 0; i < flash_status.component_cnt; i++) {
        if (address == component_id_to_i2c_addr(crypto[i].component_id)) {
            dest_config = &crypto[i];
            break;
        }
    }
    if (!dest_config)
        panic();
    int result = ap_receive(receive_buffer, dest_config);
    if (result <= 0)
        panic();
    cpyout_raw_bu8(buffer, receive_buffer, result);
    // set_state(0);
    return result;
}

int get_provisioned_ids(uint32_t *buffer) {
    memcpy(buffer, flash_status.component_ids,
           flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

// Intialising device
// Need to put the keygen stuff in this function specifically when using flash
void init() {
    __enable_irq();
    // ADD_HERE_NOP
    init_rng();
    // ADD_HERE_NOP
    switch_internal_clock();
    // ADD_HERE_NOP
    disable_extra();
    // ADD_HERE_NOP
    flash_simple_init();
    // ADD_HERE_NOP
    flash_simple_read(FLASH_ADDR, (uint32_t *)&flash_status,
                      sizeof(flash_entry_ap_t));
    // ADD_HERE_NOP

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.state = STATE_OK;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids,
               COMPONENT_CNT * sizeof(uint32_t));
        flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status,
                           sizeof(flash_entry_ap_t));
    }
    for (uint32_t i = 0; i < flash_status.component_cnt; i++)
        set_u8(verified, i, 0);
    // ADD_HERE_NOP
    if (flash_status.state == STATE_PANIC) {
        for (int i = 0; i < 30; i++) {
            spin();
            MXC_Delay(105000);
        }
    }

    // Initialize board link
    board_link_init();
}

void set_state(flash_state_t state) {
    flash_status.state = state;
    flash_simple_erase_page(FLASH_ADDR);
    flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status,
                       sizeof(flash_entry_ap_t));
}

int insecure_handshake(uint32_t component_id, buf_u8 transmit, buf_u8 receive) {
    // Send message
    int result = send_packet_and_ack(component_id, transmit);
    if (result != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }
    // Receive message
    int len = poll_and_receive_packet(component_id, receive);
    if (len == ERROR_RETURN) {
        panic();
        return ERROR_RETURN;
    }
    return len;
}

int issue_cmd(uint32_t component_id, buf_u8 transmit, buf_u8 receive) {
    // Send message

    crypto_config *dest_config = NULL;
    for (uint32_t i = 0; i < flash_status.component_cnt; i++) {
        if (component_id == crypto[i].component_id) {
            dest_config = &crypto[i];
            break;
        }
    }
    if (dest_config == NULL) {
        panic();
        return ERROR_RETURN;
    }

    int result =
        ap_send(transmit, dest_config); // Need to define the keys and stuff
    if (result != SUCCESS_RETURN) {
        return result;
    }
    // Receive message
    int len = ap_receive(receive, dest_config);
    if (len <= 0) {
        return ERROR_RETURN;
    }
    return len;
}

// Component Functions

uint32_t scan_components() {
    MXC_Delay(500000);
    // Print out provisioned component IDs
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        print_info("P>0x%08x\n", flash_status.component_ids[i]);
    }

    for (uint32_t i = 0x8; i < 0x78; i++) {
        // Create command message
        i2c_addr_t addr = component_id_to_i2c_addr(i);
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }
        set_u8(transmit_buffer, 0, COMPONENT_CMD_SCAN);
        
        int len = insecure_handshake(i, slice_bu8(transmit_buffer, 0, 1),
                                     receive_buffer);

        // Send out command and receive result

        // Success, device is present
        if (len == 4) {
            scan_message *scan = (scan_message *)receive_buffer.data;
            print_info("F>0x%08x\n", scan->component_id);
        }
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

uint32_t boot_components() {
    // Called after validation is done
    // Send boot command to each component
    char boot_msgs[flash_status.component_cnt][255];
    for (uint32_t i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        // Create command message
        set_u8(transmit_buffer, 0, COMPONENT_CMD_BOOT);
        spin();
        // Send out command and receive result
        uint32_t len =
            issue_cmd(flash_status.component_ids[i],
                      slice_bu8(transmit_buffer, 0, 1), receive_buffer);
        if (len <= 0) {
            panic();
            return ERROR_RETURN;
        }

        // // Print boot message from component
        // if(verify_string(receive_buffer.data, len) == 0)
        // panic();
        cpyout_raw_bu8((uint8_t *)boot_msgs[i], receive_buffer, len);
    }
    // Print out boot messages
    for(uint32_t i = 0; i < flash_status.component_cnt; i++) {
        print_info("0x%08x>%s\n", flash_status.component_ids[i], boot_msgs[i]);
    }
    return SUCCESS_RETURN;
}

void boot() {
// set_state(0);
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

// Compare the entered PIN to the correct PIN in hashed form
void read_and_validate_pin() {
    char buf[50] = {0};
    recv_input("Enter PIN: ", buf, 50);
    // char is 1 byte and uint8_t is 1 byte
    INIT_BUF_U8(hash, 32);
    byte salt[32] = {PIN_SALT};
    for (int i = 0; i < 32; i++) {
        buf[i + 6] = salt[i];
    }
    if (wc_Sha3_256Hash((const byte *)buf, 6 + 32, (uint8_t *)hash.data) != 0)
        panic();
    spin();
    uint8_t pin_buf[] = {AP_PIN_HASH};
    buf_u8 hashed_pin = {.data = pin_buf, .size = 32};

    if (cmp_bu8(hash, hashed_pin)) {
        return;
    }
    panic();
}

// Function to validate the replacement token in hashed form
void read_and_validate_token() {
    char buf[50] = {0};
    recv_input("Enter Token: ", buf, 50);
    // char is 1 byte and uint8_t is 1 byte
    INIT_BUF_U8(hash, 32);
    byte salt[32] = {TOKEN_SALT};
    for (int i = 0; i < 32; i++) {
        buf[i + 16] = salt[i];
    }
    spin();
    if (wc_Sha3_256Hash((const byte *)buf, 16 + 32, (uint8_t *)hash.data) != 0)
        panic();
    uint8_t token_buf[] = {AP_TOKEN_HASH};
    buf_u8 hashed_token = {.data = token_buf, .size = 32};

    if (cmp_bu8(hash, hashed_token)) {
        return;
    }
    panic();
}

// Replace a component if the PIN is correct
void attempt_replace() {
    char buf[50];
    MXC_Delay(2500000);
    spin();
    read_and_validate_token();

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
            MXC_Delay(1500000);
            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            set_u8(verified, i, 0);
            flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status,
                               sizeof(flash_entry_ap_t));
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    panic();
}

uint8_t validate_components() {
    // Called after scan is done
    // Send validate command to each component
    for (uint32_t i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        if (access_u8(verified, i) == 1) {
            continue;
        }
        spin();
        if (ap_auth(flash_status.component_ids[i], master_key, &crypto[i]) !=
            SUCCESS_RETURN) {
            panic();
            return ERROR_RETURN;
        }
        MXC_Delay(800000/flash_status.component_cnt);
        set_u8(verified, i, 1);
    }
    return SUCCESS_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    
    if (validate_components() != SUCCESS_RETURN) {
        panic();
        return;
    }
    spin();
    if (boot_components() != SUCCESS_RETURN) {
        panic();
        return;
    }
    // if(verify_string(AP_BOOT_MSG, strlen(AP_BOOT_MSG)) == 0)
    // panic();
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

int attest_component(uint32_t component_id) {
    // Buffers for board link communication
    MXC_Delay(1000000);
    uint32_t i;
    bool found = false;
    for (i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id) {
            found = true;
            break;
        }
    }
    if (!found) {
        panic();
        return ERROR_RETURN;
    }
    if (access_u8(verified, i) == 0) {
        spin();
        if (ap_auth(flash_status.component_ids[i], master_key, &crypto[i]) !=
            SUCCESS_RETURN) {
            panic();
            return ERROR_RETURN;
        }
        set_u8(verified, i, 1);
    }

    // Create command message
    set_u8(transmit_buffer, 0, COMPONENT_CMD_ATTEST);

    // Send out command and receive result
    // int len = issue_cmd(component_id, slice_bu8(transmit_buffer,0,1),
    // receive_buffer);
    int len = ap_send(slice_bu8(transmit_buffer, 0, 1), &crypto[i]);
    if (len != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }

    print_info("C>0x%08x\n", component_id);
    len = ap_receive(receive_buffer, &crypto[i]);
    if (len == ERROR_RETURN) {
        panic();
        return ERROR_RETURN;
    }
    // Print out attestation data location
    print_info("%s", receive_buffer.data);
    // if(verify_string(receive_buffer.data, len) == 0)
    // panic();
    len = ap_receive(receive_buffer, &crypto[i]);
    if (len == ERROR_RETURN) {
        panic();
        return ERROR_RETURN;
    }
    // // Print out attestation data date
    // if(verify_string(receive_buffer.data, len) == 0)
    // panic();
    print_info("%s", receive_buffer.data);
    len = ap_receive(receive_buffer, &crypto[i]);
    if (len == ERROR_RETURN) {
        panic();
        return ERROR_RETURN;
    }
    // Print out attestation data customer
    // if(verify_string(receive_buffer.data, len) == 0)
    // panic();
    print_info("%s", receive_buffer.data);
    return SUCCESS_RETURN;
}

// Attest a component if the PIN is correct
void attempt_attest() {
    char buf[50];
    spin();
    read_and_validate_pin();
    uint32_t component_id;
    recv_input("Component ID: ", buf, 50);
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

int main() {
    // Initialize board
    // ADD_HERE_NOP
    init();
    // Print the component IDs to be helpful
    // Your design does not need to do this    
    set_state(STATE_OK);
    // Handle commands forever
    char buf[100];
    while (1) {
        // set_state(1);
        fgets(buf, 100, stdin);

        // Execute requested command
        if (!strncmp(buf, "list", 4)) {
            scan_components();
        } else if (!strncmp(buf, "boot", 4)) {
            attempt_boot();
        } else if (!strncmp(buf, "replace", 7)) {
            attempt_replace();
        } else if (!strncmp(buf, "attest", 6)) {
            attempt_attest();
        } else {
            panic();
        }
        // set_state(0);
    }

    // Code never reaches here
    return 0;
}
