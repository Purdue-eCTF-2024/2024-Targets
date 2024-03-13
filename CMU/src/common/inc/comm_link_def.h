/**
 * @file comm_link_def.h
 * @author Plaid Parliament of Pwning
 * @brief Common defines for link layer
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// error code
typedef int32_t link_ret_t;
#define LINK_OK 0
#define LINK_ERR_TIMEOUT -1   // Timeout
#define LINK_ERR_BUS -2       // Bus discipline violation
#define LINK_ERR_TIMING -3    // Timing violation
#define LINK_ERR_SIZE -4      // Incorrect message size
#define LINK_ERR_CHECKSUM -5  // Incorrect message checksum
#define LINK_ERR_ADDRESS -6   // Invalid sender-receiver pair
#define LINK_ERR_SENDER -7    // Unexpected sender
#define LINK_ERR_RECEIVER -8  // This board is not the receiver

/**
 * @brief The maximum size of the message that can be sent
 */
#define LINK_MAX_MESSAGE_SIZE ((size_t)400)
// LINK_MAX_PACKET_SIZE is derived from this value

#define LINK_MAX_TIMEOUT_MS ((int32_t)5000)
// MUST be <= LINK_MAX_TIMEOUT_TICKS / LINK_NUM_TICKS_PER_MS
// 2^31 / 2 / (30 MHz / 1k ms/s) == 35791 ms

/**
 * @brief Macro function to check if a 32-bit value can fit in int32_t
 */
#define LINK_CAN_FIT_IN_INT32(x) (!((uint32_t)(x) >> 31U))
