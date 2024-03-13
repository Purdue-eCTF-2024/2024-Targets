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

int sec_link_respond(uint8_t *send_buf, size_t len);

int64_t sec_link_receive_and_send_ack(uint8_t *receive_buf, size_t max_len);
