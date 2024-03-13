/**
 * @file ap_secure_comm.h
 * @author Plaid Parliament of Pwning
 * @brief Prototypes for secure send/receive functions
 *
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once
#include <stdint.h>
#include "comm_link_def.h"

int secure_send(uint8_t address, uint8_t* buffer, uint8_t len);
int secure_receive(uint8_t address, uint8_t* buffer);
int get_provisioned_ids(uint32_t *ids);