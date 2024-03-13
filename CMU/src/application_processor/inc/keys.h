/**
 * @file keys.h
 * @author Plaid Parliament of Pwning
 * @brief Constants for addresses of keys
 * 
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once
#include <stdint.h>

#define ATT_ROOT_KEY_ENCRYPTED ((uint8_t *)0x10044000)
#define AP_BOOT_ROOT_KEY ((uint8_t *)0x10044048)
#define DEPLOYMENT_KEY ((uint8_t *)0x10044090)
#define NONCE_KEY ((uint8_t *)0x100440B0)
