/**
 * @file "ap_postboot.h"
 * @brief Post-Boot-related functions for AP
 */

#ifndef _AP_POSTBOOT_H_
#define _AP_POSTBOOT_H_

#include "ap_common.h"

int secure_send(uint8_t address, uint8_t* buffer, uint8_t len);
int secure_receive(i2c_addr_t address, uint8_t* buffer);
int get_provisioned_ids(uint32_t* buffer);

#endif
