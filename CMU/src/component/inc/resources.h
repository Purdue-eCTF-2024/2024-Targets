/**
 * @file resources.h
 * @author Plaid Parliament of Pwning
 * @brief Struct and constants for the component to boot and function
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include "crypto_wrappers.h"
#include "attestation_data.h"
#include "comm_types.h"

#include <stdint.h>

typedef struct {
	uint32_t id;
	uint8_t ap_boot_subkey[CC_ENC_SYM_KEY_LEN];
	encrypted_att_data_t encrypted_att_data;
	uint8_t deployment_key[CC_ENC_SYM_KEY_LEN];
	uint8_t nonce_key[CC_ENC_SYM_KEY_LEN];
} Resources;

#define RESOURCES_FLASH ((Resources *)0x10044000)

#define COMPONENT_ID (RESOURCES_FLASH->id)
#define AP_BOOT_SUBKEY (RESOURCES_FLASH->ap_boot_subkey)
#define ENCRYPTED_ATT_DATA (RESOURCES_FLASH->encrypted_att_data)
#define DEPLOYMENT_KEY (RESOURCES_FLASH->deployment_key)
#define NONCE_KEY (RESOURCES_FLASH->nonce_key)
