/**
 * @file boot_blob.h
 * @author Plaid Parliament of Pwning
 * @brief Struct for boot data
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include <stdint.h>

#include "crypto_wrappers.h"

#define BOOT_MSG_LEN 64
typedef struct {
	uint8_t comp_code_key        [CC_ENC_SYM_KEY_LEN];
	uint8_t secure_send_subkey[CC_ENC_SYM_KEY_LEN];
	uint8_t boot_msg          [BOOT_MSG_LEN];
} boot_blob;

#define ENCRYPTED_BOOT_BLOB_LEN (CC_ENC_SYM_METADATA_LEN + sizeof(boot_blob))

__attribute__((aligned(4))) // To make sure we can copy it into flash through a uint32_t*
typedef struct {
	uint8_t encrypted_boot_blob[ENCRYPTED_BOOT_BLOB_LEN];
} boot_blob_page_t;

#define BOOT_BLOB_FLASH ((boot_blob_page_t*)0x1003E000)