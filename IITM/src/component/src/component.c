#include <board.h>
#include <i2c.h>
#include <led.h>
#include <mxc_delay.h>
#include <mxc_errors.h>
#include <nvic_table.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

// deployment
#include <ectf_params.h>
#include <global_secrets.h>

// custom packages
#include <crypto_wolfssl.h>
#include <helper_functions.h>
#include <secure_buffer.h>
#include <secure_host_messaging.h>
#include <simple_flash.h>

// component libraries
#include <boardlink_component.h>
#include <secure_component.h>
#include <simple_i2c_component.h>

#ifdef POST_BOOT
#include <led.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

// ==== COMMAND PROCESSING FUNCTIONS ====
/**
 * Process a command stored in the receive buffer.
 */
void component_process_cmd();
/**
 * Process a boot command.
 */
void process_boot();
/**
 * Process a scan command.
 */
void process_scan();
/**
 * Process an attest command.
 */
void process_attest();

// ==== PERIPHERALS ====
/**
 * Security status of this component.
 */
flash_entry_component_t flash_status;

/**
 * Initialize peripherals and read flash_status
 */
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
                      sizeof(flash_entry_component_t));
    // ADD_HERE_NOP

    if (flash_status.flash_magic != FLASH_MAGIC) {
        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.state = STATE_OK;
        flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status,
                           sizeof(flash_entry_component_t));
    }
    // ADD_HERE_NOP
    if (flash_status.state == STATE_PANIC) {
        for (int i = 0; i < 30; i++) {
            spin();
            MXC_Delay(105000);
        }
    }

    // Initialize board link
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);
}

// ==== COMMUNICATION ====
/**
 * Key generated after authenticating with AP.
 */
crypto_config key;

INIT_BUF_U8(receive_buffer, MAX_I2C_MESSAGE_LEN);
INIT_BUF_U8(transmit_buffer, MAX_I2C_MESSAGE_LEN);

uint8_t key_buf[] = {MASTER_KEY};
buf_u8 master_key = {.data = key_buf, .size = MASTER_KEY_COUNT * KEY_LEN_BYTES};

// Secure Communication
// These functions will be externed from the secure library

void secure_send(uint8_t *data, uint8_t len) {
    // set_state(1);
    cpyin_raw_bu8(transmit_buffer, data, len);
    spin();
    if (component_send(slice_bu8(transmit_buffer, 0, len), &key) !=
        SUCCESS_RETURN)
        panic();
    // set_state(0);
}

int secure_receive(uint8_t *buffer) {
    // set_state(1);
    int len = wait_and_receive_packet(receive_buffer);
    if (len <= 0)
        panic();
    int ret = component_receive(slice_bu8(receive_buffer, 0, len), &key);
    if (ret <= 0)
        panic();
    spin();
    cpyout_raw_bu8(buffer, receive_buffer, ret);
    // set_state(0);
    return ret;
}

void clear_buffer(char *buffer, uint32_t size) {
    memset(buffer, 0, size);
}

void set_state(flash_state_t state) {
    flash_status.state = state;
    flash_simple_erase_page(FLASH_ADDR);
    flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status,
                       sizeof(flash_entry_component_t));
}

bool check_auth() {
    INIT_BUF_U8(auth_buf, 4);
    set_u8(auth_buf, 0, 'A');
    set_u8(auth_buf, 1, 'U');
    set_u8(auth_buf, 2, 'T');
    set_u8(auth_buf, 3, 'H');
    return cmp_bu8(slice_bu8(receive_buffer, 0, 4), auth_buf);
}

void component_process_cmd() {
    uint8_t opcode = access_u8(receive_buffer, 0);
    // Output to application processor dependent on command received
    switch (opcode) {
    case COMPONENT_CMD_BOOT:
        process_boot();
        break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        panic();
        break;
    }
}

void boot() {
// set_state(0);
// POST BOOT FUNCTIONALITY
// DO NOT REMOVE IN YOUR DESIGN
#ifdef POST_BOOT
    POST_BOOT
#else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
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

void process_scan() {
    scan_message msg;
    msg.component_id = COMPONENT_ID;
    cpyin_raw_bu8(transmit_buffer, (uint8_t *)&msg, sizeof(scan_message));
    if (send_packet_and_ack(slice_bu8(transmit_buffer, 0, 4)) !=
        SUCCESS_RETURN) {}
    spin();
}

void process_boot() {
    uint32_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    char boot_msg[] = COMPONENT_BOOT_MSG;
    cpyin_raw_bu8(transmit_buffer, (uint8_t *)boot_msg, len);
    spin();
    // encrypt and send boot message
    if (component_send(slice_bu8(transmit_buffer, 0, len), &key))
        panic();
    boot();
}

void process_attest() {
    char attest_msg[MAX_I2C_MESSAGE_LEN];

    uint32_t len = 1 + snprintf((char *)attest_msg, MAX_I2C_MESSAGE_LEN,
                                "LOC>%s\n", ATTESTATION_LOC);
    cpyin_raw_bu8(transmit_buffer, (uint8_t *)attest_msg, len);
    if (component_send(slice_bu8(transmit_buffer, 0, len), &key))
        panic();
    clear_buffer(attest_msg, MAX_I2C_MESSAGE_LEN);
    spin();

    len = 1 + snprintf((char *)attest_msg, MAX_I2C_MESSAGE_LEN, "DATE>%s\n",
                       ATTESTATION_DATE);
    cpyin_raw_bu8(transmit_buffer, (uint8_t *)attest_msg, len);
    if (component_send(slice_bu8(transmit_buffer, 0, len), &key))
        panic();
    clear_buffer(attest_msg, MAX_I2C_MESSAGE_LEN);

    len = 1 + snprintf((char *)attest_msg, MAX_I2C_MESSAGE_LEN, "CUST>%s\n",
                       ATTESTATION_CUSTOMER);
    cpyin_raw_bu8(transmit_buffer, (uint8_t *)attest_msg, len);
    if (component_send(slice_bu8(transmit_buffer, 0, len), &key))
        panic();
}

int main() {
    // Initialize Component
    // ADD_HERE_NOP
    init();
    set_state(STATE_OK);
    int auth = ERROR_RETURN;
    while (1) {
        int len = wait_and_receive_packet(receive_buffer);
        // spin();
        if (len == 1 && access_u8(receive_buffer, 0) == COMPONENT_CMD_SCAN) {
            process_scan();
            continue;
        }
        spin();
        if (auth == ERROR_RETURN && check_auth() == true) {
            auth =
                component_auth(COMPONENT_ID, slice_bu8(receive_buffer, 0, len),
                               master_key, &key);
            continue;
        }
        spin();
        if (auth == SUCCESS_RETURN && len > 0) {
            len = component_receive(slice_bu8(receive_buffer, 0, len),
                                    &key); // Decrypts the received message
            if (len <= 0) {
                panic();
            }

            component_process_cmd();
            continue;
        }
        panic();
        // set_state(0);
    }
}
