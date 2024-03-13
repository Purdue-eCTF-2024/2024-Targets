/**
 * @file component_secure_comm.h
 * @author Plaid Parliament of Pwning
 * @brief Prototypes for secure send/receive
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once
#include <stdint.h>

void secure_send(uint8_t* buffer, uint8_t len);
int secure_receive(uint8_t* buffer);