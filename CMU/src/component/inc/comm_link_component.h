/**
 * @file comm_link_component.h
 * @author Plaid Parliament of Pwning
 * @brief Link layer prototypes for component related functionality
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "comm_link_def.h"

void link_init(); 

link_ret_t link_respond(const uint8_t *send_buf, size_t message_size);

int32_t link_receive_and_send_ack(uint8_t *receive_buf,
                                  size_t max_message_size);
