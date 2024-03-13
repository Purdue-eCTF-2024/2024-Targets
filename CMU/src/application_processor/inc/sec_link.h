/**
 * @file sec_link.h
 * @author Plaid Parliament of Pwning
 * @brief Prototypes for secure wrapper over link layer
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

int sec_link_init(void);

int sec_link_send_and_wait_ack(uint8_t *send_buf, size_t len, uint8_t unenforced_i2c_addr, int32_t ack_timeout_ms);

int32_t sec_link_receive(uint8_t *receive_buf, size_t max_len, uint8_t unenforced_i2c_addr);

int sec_link_poll(uint8_t unenforced_i2c_addr, int32_t ack_timeout_ms);
