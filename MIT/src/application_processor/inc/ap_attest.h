/**
 * @file "ap_attest.h"
 * @brief Attest-related functions for AP
 */

#ifndef _AP_ATTEST_H_
#define _AP_ATTEST_H_

#include "ap_common.h"

// Send attestation request to specific component
int attest_component(uint32_t component_id);

// Attest a component if the PIN is correct
int attempt_attest(void);

#endif
