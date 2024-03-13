/**
 * @file comm_link_phy.h
 * @author Plaid Parliament of Pwning
 * @brief Structs and prototypes for the physical layer communications
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "comm_link_def.h"

// The header of a packet
// MUST NOT contain implicit padding because it defines the header's byte format
typedef struct {
    uint32_t checksum;
    uint16_t message_size;
    uint8_t sender_address;
    uint8_t receiver_address;
} link_header_t;

#define LINK_HEADER_SIZE ((size_t)sizeof(link_header_t))
#define LINK_MAX_PACKET_SIZE (LINK_HEADER_SIZE + LINK_MAX_MESSAGE_SIZE)
#define LINK_CHECKSUM_SIZE ((size_t)sizeof(uint32_t))

void link_init_gpio(void);

link_ret_t link_send_serialized_packet(const uint8_t *serialized_packet_buf,
                                       size_t serialized_packet_size);

int32_t link_receive_serialized_packet(uint8_t *serialized_packet_buf,
                                       size_t max_message_size);

void link_send_ack(void);

link_ret_t link_wait_ack(uint32_t timeout_ticks);
