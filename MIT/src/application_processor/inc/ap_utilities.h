/**
 * @file "ap_utilities.h"
 * @brief Misc utilities for AP
 */

#ifndef _AP_UTILITIES_H_
#define _AP_UTILITIES_H_

#include "ap_common.h"

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint32_t timeout;
    uint32_t component_cnt;
    uint32_t component_ids[32];
} flash_entry;

/********************************* UTILITIES **********************************/

// Reset nonces for our i2c comms sessions
void session_init(void);

mit_session_t * get_session_of_component(mit_comp_id_t component_id);

// Return component_id stored in slot `id`
mit_comp_id_t get_component_id(uint8_t id);

// Return ptr to flash_status
flash_entry * get_flash_status(void);

// Test application has been booted before
void flash_first_boot(void);

// Rewrite our provisioned component info into flash
void rewrite_flash_entry(void);

// Fetch status of timeout, which persists across reboots in case of bad Attestation PIN guesses
bool get_attest_timeout(void);

// Clear the timeout status
void unset_attest_timeout(void);

// Enable timeouts on future Attestation PIN guesses
void set_attest_timeout(void);

// Validate packet in the receive buffer
int validate_rx_packet(mit_comp_id_t component_id, mit_opcode_t expected_opcode);

// Send a command to a component and receive the result
int issue_cmd(mit_comp_id_t component_id, mit_opcode_t expected_opcode);

// Send packet at *packet to addr
int send_mit_packet(i2c_addr_t addr, mit_packet_t * packet);

// Checks if component id is currently provisioned
bool is_valid_component(mit_comp_id_t component_id);

// Helper to construct packet, stores in transmit_buffer
int make_mit_packet(mit_comp_id_t component_id, mit_opcode_t opcode, uint8_t * data, uint8_t len);

/******************************* PTRS ********************************/
mit_packet_t * get_rx_packet(void);
mit_packet_t * get_tx_packet(void);
uint8_t * get_i2c_rx_buffer(void);

#endif
