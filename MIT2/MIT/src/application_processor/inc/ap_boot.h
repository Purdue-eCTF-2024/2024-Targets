/**
 * @file "ap_boot.h"
 * @brief Boot-related functions for AP
 */

#ifndef _AP_BOOT_H_
#define _AP_BOOT_H_

#include "ap_common.h"

// Boot the components and board if the components validate
int attempt_boot(void);

// Command AP to boot
void boot_ap(void);

#endif
