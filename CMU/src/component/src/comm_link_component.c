#include "comm_link_component.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "comm_link.h"
#include "comm_link_def.h"

/**
 * @brief Respond to AP over link layer
 * 
 * Waiting for ACK is always a NOP on a Component, ack_timeout_ms will be ignored.
 * 
 * @param send_buf buffer to send
 * @param message_size length of the buffer
 * @return 0 on success, negative on error
 */
link_ret_t link_respond(const uint8_t *send_buf, size_t message_size) {
    return link_send_message_and_wait_ack(send_buf, message_size,
                                          LINK_AP_ADDRESS, -1);
}

/**
 * @brief Receives data over the link and sends an ack
 * 
 * @param receive_buf buffer to receive data into
 * @param max_message_size max size of the buffer
 * @return int32_t actual size of the data received
 */
int32_t link_receive_and_send_ack(uint8_t *receive_buf,
                                  size_t max_message_size) {
    return link_receive_message_and_send_ack(receive_buf, max_message_size,
                                             LINK_AP_ADDRESS);
}
