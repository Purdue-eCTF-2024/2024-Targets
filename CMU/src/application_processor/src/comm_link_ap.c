#include "comm_link_ap.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "comm_link.h"
#include "comm_link_def.h"

/**
 * @brief Send a message from AP and wait for an ack
 *
 * @param send_buf contains the message to send
 * @param message_size message size
 * @param unenforced_i2c_addr expected address of the receiver
 * @param ack_timeout_ms wait timeout for ack
 * @return 0 on success, negative on error
 */
link_ret_t link_send_and_wait_ack(const uint8_t *send_buf, size_t message_size,
                                  uint8_t unenforced_i2c_addr,
                                  int32_t ack_timeout_ms) {
    return link_send_message_and_wait_ack(send_buf, message_size,
                                          unenforced_i2c_addr, ack_timeout_ms);
}

/**
 * @brief Receive a message from the component
 * 
 * Sending the ACK is a NOP on the AP.
 * 
 * @param receive_buf receive buffer where the message is filled
 * @param max_message_size max size that can be received
 * @param unenforced_i2c_addr expected address of the sender
 * @return int32_t returns the actual size of the message received
 */
int32_t link_receive(uint8_t *receive_buf, size_t max_message_size,
                     uint8_t unenforced_i2c_addr) {
    return link_receive_message_and_send_ack(receive_buf, max_message_size,
                                             unenforced_i2c_addr);
}
