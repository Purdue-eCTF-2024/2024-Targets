/**
 * @file attestation_data.h
 * @author Plaid Parliament of Pwning
 * @brief Structs for attestation data
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */

#pragma once
#include <stdint.h>

#include "crypto_wrappers.h"

#define BOOT_MSG_LEN 64
#define ATTEST_INFO_LEN 64

/**
 * @brief Struct for attestation data
 */
typedef struct {
	uint8_t location[ATTEST_INFO_LEN];
	uint8_t date    [ATTEST_INFO_LEN];
	uint8_t customer[ATTEST_INFO_LEN];
} att_data_t;

#define ENCRYPTED_ATT_DATA_LEN \
	sizeof(att_data_t) + CC_ENC_SYM_METADATA_LEN

/**
 * @brief Convenience type for encrypted attestation data
 */
typedef struct {
    uint8_t data[ENCRYPTED_ATT_DATA_LEN];
} encrypted_att_data_t;

