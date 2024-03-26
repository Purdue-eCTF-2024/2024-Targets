/**
 * @file "ap_common.h"
 * @brief Common include-all header for AP files
 */

#ifndef _AP_COMMON_H_
#define _AP_COMMON_H_

#include <stdint.h>

#define AP_PLAINTEXT_LEN 256
extern uint8_t ap_plaintext[AP_PLAINTEXT_LEN];

// MITRE-provided headers
#include "board_link.h"
#include "host_messaging.h"
#include "simple_flash.h"
#include "simple_i2c_controller.h"

// Deployment-related headers
#include "ectf_params.h"
#include "global_secrets.h"

// Common AP+Component headers
#include "common_crypto.h"
#include "common_delay.h"
#include "common_init.h"
#include "common_msg.h"
#include "simple_trng.h"

// AP-related logic
#include "ap_attest.h"
#include "ap_boot.h"
#include "ap_list.h"
#include "ap_postboot.h"
#include "ap_replace.h"
#include "ap_session.h"
#include "ap_utilities.h"

// Prehashed secrets :-)
#include "prehashed.h"

#include "return_codes.h"

#endif
