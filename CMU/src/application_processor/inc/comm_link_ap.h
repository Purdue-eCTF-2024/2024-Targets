#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "comm_link_def.h"

void link_init(void); 

link_ret_t link_send_and_wait_ack(const uint8_t *send_buf, size_t message_size,
                                  uint8_t unenforced_i2c_addr,
                                  int32_t ack_timeout_ms);

int32_t link_receive(uint8_t *receive_buf, size_t max_message_size,
                     uint8_t unenforced_i2c_addr);
