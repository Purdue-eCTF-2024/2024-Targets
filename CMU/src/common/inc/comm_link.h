/**
 * @file comm_link.h
 * @author Plaid Parliament of Pwning
 * @brief Prototypes for link layer exposed to other files
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "comm_link_def.h"

/**
 * @brief The AP's address, MUST be a reserved I2C address
 */
#define LINK_AP_ADDRESS ((uint8_t)0)

link_ret_t link_send_message_and_wait_ack(const uint8_t *send_buf,
                                          size_t message_size,
                                          uint8_t receiver_address,
                                          int32_t ack_timeout_ms);

int32_t link_receive_message_and_send_ack(uint8_t *receive_buf,
                                          size_t max_message_size,
                                          uint8_t expected_sender_address);

bool is_valid_i2c_address(uint8_t i2c_address);

uint8_t component_id_to_i2c_address(uint32_t component_id);
