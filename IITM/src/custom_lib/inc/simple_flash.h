/**
 * @file "simple_flash.h"
 * @author Frederich Stine
 * @brief Simple Flash Interface Header
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2024 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#ifndef __SIMPLE_FLASH__
#define __SIMPLE_FLASH__

#include <stdint.h>

#include "mxc_device.h"

// Flash Macros
#define FLASH_ADDR                                                             \
    ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
// Magic number is moved to global secrets

/**
 * State stored in the flash.
 */
typedef enum {
    STATE_OK,
    STATE_PANIC
} flash_state_t;

// Datatype for information stored in flash
// add checksum // Not needed since if flash access is present no way of
// bypassing this
typedef struct {
    uint32_t flash_magic;
    flash_state_t state;
    uint32_t component_cnt;
    uint32_t component_ids[32]; // Array of component ids,
} flash_entry_ap_t;

// add checksum // Not needed since if flash access is present no way of
// bypassing this
typedef struct {
    uint32_t flash_magic;
    flash_state_t state;
} flash_entry_component_t;

/**
 * @brief Initialize the Simple Flash Interface
 *
 * This function registers the interrupt for the flash system,
 * enables the interrupt, and disables ICC
 */
void flash_simple_init(void);
/**
 * @brief Flash Simple Erase Page
 *
 * @param address: uint32_t, address of flash page to erase
 *
 * @return int: return negative if failure, zero if success
 *
 * This function erases a page of flash such that it can be updated.
 * Flash memory can only be erased in a large block size called a page.
 * Once erased, memory can only be written one way e.g. 1->0.
 * In order to be re-written the entire page must be erased.
 */
int flash_simple_erase_page(uint32_t address);
/**
 * @brief Flash Simple Read
 *
 * @param address: uint32_t, address of flash page to read
 * @param buffer: uint32_t*, pointer to buffer for data to be read into
 * @param size: uint32_t, number of bytes to read from flash
 *
 * This function reads data from the specified flash page into the buffer
 * with the specified amount of bytes
 */
void flash_simple_read(uint32_t address, uint32_t *buffer, uint32_t size);
/**
 * @brief Flash Simple Write
 *
 * @param address: uint32_t, address of flash page to write
 * @param buffer: uint32_t*, pointer to buffer to write data from
 * @param size: uint32_t, number of bytes to write from flash
 *
 * @return int: return negative if failure, zero if success
 *
 * This function writes data to the specified flash page from the buffer passed
 * with the specified amount of bytes. Flash memory can only be written in one
 * way e.g. 1->0. To rewrite previously written memory see the
 * flash_simple_erase_page documentation.
 */
int flash_simple_write(uint32_t address, uint32_t *buffer, uint32_t size);

#endif
