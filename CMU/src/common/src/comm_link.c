/**
 * @file comm_link.c
 * @author Plaid Parliament of Pwning
 * @brief Implements the link layer side of communications
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include "comm_link.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>  // For memcpy and memset

#include "comm_link_def.h"
#include "comm_link_phy.h"
#include "comm_link_tmr.h"
#include "util.h"  // For UTIL_ASSERT

/**
 * @brief For COMPONENT_ID, which only exists on the flash of a Component
 */
#if !IS_AP
#include "resources.h"
#endif  // #if !IS_AP

/********** PACKET FORMAT ***********/

/**
 * @brief All the information sent in a round of communication
 */
typedef struct {
    uint16_t message_size;
    uint8_t sender_address;
    uint8_t receiver_address;
    const uint8_t *message_buf;  // Read-only buffer
} link_sent_packet_t;

/**
 * @brief All the information received in a round of communication
 */
typedef struct {
    uint16_t message_size;
    uint8_t sender_address;
    uint8_t receiver_address;
    uint8_t *message_buf;
} link_received_packet_t;

/********** PACKET FORMAT END ***********/

/********** FORWARD DECLARATIONS ***********/

static link_ret_t link_send_packet_and_wait_ack(
    const link_sent_packet_t *packet, int32_t ack_timeout_ms);
static int32_t link_serialize_packet(const link_sent_packet_t *packet);

static link_ret_t link_receive_packet_and_send_ack(
    link_received_packet_t *packet, size_t max_message_size,
    uint8_t expected_sender_address);
static bool link_should_retry_receiving(link_ret_t ret);
static link_ret_t link_try_receive_packet_and_send_ack(
    link_received_packet_t *packet, size_t max_message_size,
    uint8_t expected_sender_address);
static link_ret_t link_deserialize_packet(
    link_received_packet_t *received_packet, size_t packet_size,
    size_t max_message_size, uint8_t expected_sender_address);
static link_ret_t link_check_address(const link_received_packet_t *packet,
                                     uint8_t expected_sender_address);

static uint32_t eval_packet_checksum(const uint8_t *packet_buf,
                                     size_t packet_size);
static uint32_t eval_fnv_1a(const uint8_t *buf, size_t len);

/********** FORWARD DECLARATIONS END ***********/

/********** BUFFERS ***********/

/**
 * @brief Buffer for the serialized packet to be sent
 */
static uint8_t link_sent_packet_buf[LINK_MAX_PACKET_SIZE + 1] = {0};

/**
 * @brief Buffer for the received serialized packet
 */
static uint8_t link_received_packet_buf[LINK_MAX_PACKET_SIZE + 1] = {0};

/********** BUFFERS END ***********/

/********** INITIALIZATION ***********/

/**
 * @brief The bitmask of a valid I2C address in 1 byte
 */
#define LINK_I2C_ADDRESS_MASK ((uint8_t)0x7f)

/**
 * @brief Define LINK_SELF_ADDRESS based on the board's type and ID
 */
#if IS_AP
#define LINK_SELF_ADDRESS LINK_AP_ADDRESS
#else  // !IS_AP
#define LINK_SELF_ADDRESS (((uint8_t)COMPONENT_ID) & LINK_I2C_ADDRESS_MASK)
#endif  // #if IS_AP

/**
 * @brief Flag to indicate whether link layer is intialized or not
 */
static bool link_initialized = false;

/**
 * @brief Initializes the link layer
 * 
 * Does some sanity checking for the addresses and initializes the GPIO pins
 */
void link_init(void) {
    UTIL_ASSERT(!link_initialized);

    if (IS_AP) {
        // The AP's address must be LINK_AP_ADDRESS
        UTIL_ASSERT(LINK_SELF_ADDRESS == LINK_AP_ADDRESS);
        UTIL_ASSERT(!is_valid_i2c_address(LINK_SELF_ADDRESS));
    } else {
        // A Component's address must be a valid I2C address
        UTIL_ASSERT(is_valid_i2c_address(LINK_SELF_ADDRESS));
    }

    link_init_gpio();

    link_initialized = true;
}

/********** INITIALIZATION END ***********/

/********** SEND ***********/

/**
 * @brief Wrapper function to send message and wait on ack
 * 
 * @param send_buf buffer that contains the message
 * @param message_size the size of the message to send
 * @param receiver_address address of the receiver
 * @param ack_timeout_ms wait timeout for ack in ms
 * @return link_ret_t returns 0 on success, negative on error
 */
link_ret_t link_send_message_and_wait_ack(const uint8_t *send_buf,
                                          size_t message_size,
                                          uint8_t receiver_address,
                                          int32_t ack_timeout_ms) {
    UTIL_ASSERT(send_buf);
    UTIL_ASSERT(message_size <= LINK_MAX_MESSAGE_SIZE);

    link_sent_packet_t packet;
    packet.message_size = (uint16_t)message_size;
    packet.sender_address = LINK_SELF_ADDRESS;
    packet.receiver_address = receiver_address;
    packet.message_buf = send_buf;

    return link_send_packet_and_wait_ack(&packet, ack_timeout_ms);
}

/**
 * @brief Send packet and wait on ack
 * 
 * @param packet packet to send 
 * @param ack_timeout_ms wait timeout for ack in milliseconds
 * @return link_ret_t returns 0 on success, negative on error
 */
static link_ret_t link_send_packet_and_wait_ack(
    const link_sent_packet_t *packet, int32_t ack_timeout_ms) {
    UTIL_ASSERT(link_initialized);
    UTIL_ASSERT(packet);

    const int32_t packet_size_ret = link_serialize_packet(packet);
    if (packet_size_ret < 0) {
        return packet_size_ret;  // Error code
    }
    const size_t packet_size = (size_t)packet_size_ret;

    const link_ret_t send_ret =
        link_send_serialized_packet(link_sent_packet_buf, packet_size);
    if (send_ret != LINK_OK) {
        return send_ret;  // Error code
    }

    const uint32_t ack_timeout_ticks = link_timeout_ms_to_ticks(ack_timeout_ms);
    return link_wait_ack(ack_timeout_ticks);
}

/**
 * @brief Serializes the packet and headers onto to the global buffer link_sent_packet_buf
 *
 *  This function also calculates and attaches the checksum.
 * 
 * @param packet packet to be serialzed
 * @return size of the packet if non-negative; error code if negative
 */
static int32_t link_serialize_packet(const link_sent_packet_t *packet) {
    UTIL_ASSERT(packet);

    // The AP must have address LINK_AP_ADDRESS
    UTIL_ASSERT(!IS_AP || packet->sender_address == LINK_AP_ADDRESS);

    // A component must NOT have address LINK_AP_ADDRESS
    UTIL_ASSERT(IS_AP || packet->sender_address != LINK_AP_ADDRESS);

    const size_t message_size = (size_t)packet->message_size;
    UTIL_ASSERT(message_size <= LINK_MAX_MESSAGE_SIZE);

    const size_t packet_size = message_size + LINK_HEADER_SIZE;
    UTIL_ASSERT(packet_size <= LINK_MAX_PACKET_SIZE);

    // Calculate buffer offsets
    link_header_t *header_buf = (link_header_t *)link_sent_packet_buf;
    uint8_t *message_buf = link_sent_packet_buf + LINK_HEADER_SIZE;

    // Populate header
    header_buf->checksum = 0;  // Not calculated yet
    header_buf->message_size = packet->message_size;
    header_buf->sender_address = packet->sender_address;
    header_buf->receiver_address = packet->receiver_address;

    // Populate message
    memcpy(message_buf, packet->message_buf, message_size);

    // Calculate checksum
    header_buf->checksum =
        eval_packet_checksum(link_sent_packet_buf, packet_size);

    UTIL_ASSERT(LINK_CAN_FIT_IN_INT32(packet_size));
    return (int32_t)packet_size;
}

/********** SEND END ***********/

/********** RECEIVE ***********/

/**
 * @brief Receive a message and send ack
 * 
 * This is mostly just a wrapper over link_receive_packet_and_send_ack
 * 
 * @param receive_buf buffer to receive the message
 * @param max_message_size max size of the message that can be received
 * @param expected_sender_address expected address of the sender
 * @return size of the packet if non-negative; error code if negative
 */
int32_t link_receive_message_and_send_ack(uint8_t *receive_buf,
                                          size_t max_message_size,
                                          uint8_t expected_sender_address) {
    UTIL_ASSERT(receive_buf);
    UTIL_ASSERT(max_message_size <= LINK_MAX_MESSAGE_SIZE);

    link_received_packet_t received_packet;
    received_packet.message_buf = receive_buf;

    const link_ret_t receive_packet_ret = link_receive_packet_and_send_ack(
        &received_packet, max_message_size, expected_sender_address);

    if (receive_packet_ret != LINK_OK) {
        return receive_packet_ret;  // Error code
    }

    UTIL_ASSERT(LINK_CAN_FIT_IN_INT32(received_packet.message_size));
    return (int32_t)received_packet.message_size;
}

/**
 * @brief Receive a packet and send ack
 * 
 * @param packet buffer to receive the packet
 * @param max_message_size max size of the packet that can be received
 * @param expected_sender_address expected address of the sender
 * @return 0 on success, negative on error
 */
static link_ret_t link_receive_packet_and_send_ack(
    link_received_packet_t *packet, size_t max_message_size,
    uint8_t expected_sender_address) {
    UTIL_ASSERT(link_initialized);
    UTIL_ASSERT(packet);
    UTIL_ASSERT(max_message_size <= LINK_MAX_MESSAGE_SIZE);

    while (true) {  // Wait indefinitely
        const link_ret_t receive_ret = link_try_receive_packet_and_send_ack(
            packet, max_message_size, expected_sender_address);

        if (receive_ret == LINK_OK) {
            return LINK_OK;  // Packet is correct
        }
        // Packet is incorrect

        if (!link_should_retry_receiving(receive_ret)) {
            return receive_ret;  // Packet is incorrect, should not retry
        }
        // Packet is incorrect, should retry
    }
}

/**
 * @brief Conditions for whether a link should try receiving again.
 * 
 * @param ret kind of error occurred
 * @return true if retry is possible, else false
 */
static bool link_should_retry_receiving(link_ret_t ret) {
    return ret == LINK_ERR_SIZE          // Wrong size (incomplete packet)
           || ret == LINK_ERR_CHECKSUM   // Wrong checksum (corrupted packet)
           || ret == LINK_ERR_RECEIVER;  // Wrong receiver (not the recipient)
}

/**
 * @brief Deserializes received packet and sends ack back
 * 
 * @param packet buffer where the received packet will be deserialized
 * @param max_message_size max size of the message that can be received
 * @param expected_sender_address expected address of the sender
 * @return 0 on success, negative on error
 */
static link_ret_t link_try_receive_packet_and_send_ack(
    link_received_packet_t *packet, size_t max_message_size,
    uint8_t expected_sender_address) {
    UTIL_ASSERT(packet);
    UTIL_ASSERT(max_message_size <= LINK_MAX_MESSAGE_SIZE);

    const int32_t packet_size_ret = link_receive_serialized_packet(
        link_received_packet_buf, max_message_size);
    if (packet_size_ret < 0) {
        return packet_size_ret;  // Error code
    }
    const size_t packet_size = (size_t)packet_size_ret;

    const link_ret_t deserialize_ret = link_deserialize_packet(
        packet, packet_size, max_message_size, expected_sender_address);
    if (deserialize_ret != LINK_OK) {
        return deserialize_ret;  // Error code
    }

    link_send_ack();  // Always succeeds

    return LINK_OK;
}

/**
 * @brief Deserializes a packet
 * 
 * @param received_packet 
 * @param packet_size size of the packet
 * @param max_message_size max size of the message
 * @param expected_sender_address expected sender's address
 * @return link_ret_t 0 on success, negative on error
 */
static link_ret_t link_deserialize_packet(
    link_received_packet_t *received_packet, size_t packet_size,
    size_t max_message_size, uint8_t expected_sender_address) {
    UTIL_ASSERT(received_packet && received_packet->message_buf);
    UTIL_ASSERT(packet_size <= LINK_MAX_PACKET_SIZE);
    UTIL_ASSERT(max_message_size <= LINK_MAX_MESSAGE_SIZE);

    if (packet_size < LINK_HEADER_SIZE) {
        return LINK_ERR_SIZE;  // Packet size smaller than its header
    }

    const size_t message_size = packet_size - LINK_HEADER_SIZE;
    if (message_size > max_message_size) {
        return LINK_ERR_SIZE;  // Message size larger than expected
    }

    // Calculate buffer offsets
    const link_header_t *header_buf = (link_header_t *)link_received_packet_buf;
    const uint8_t *message_buf = link_received_packet_buf + LINK_HEADER_SIZE;

    // Read header from buffer
    const uint32_t received_checksum = header_buf->checksum;
    received_packet->message_size = header_buf->message_size;
    received_packet->sender_address = header_buf->sender_address;
    received_packet->receiver_address = header_buf->receiver_address;

    // Verify size
    if (message_size != (size_t)received_packet->message_size) {
        return LINK_ERR_SIZE;  // Wrong message size
    }

    // Verify checksum
    const uint32_t checksum =
        eval_packet_checksum(link_received_packet_buf, packet_size);
    if (checksum != received_checksum) {
        return LINK_ERR_CHECKSUM;  // Wrong checksum
    }

    // Verify addresses
    const link_ret_t check_address_ret =
        link_check_address(received_packet, expected_sender_address);
    if (check_address_ret != LINK_OK) {
        return check_address_ret;  // Wrong sender or receiver address
    }

    // Copy over the message, with trailing space in the buffer filled with 0s
    memset(received_packet->message_buf, 0, max_message_size);
    memcpy(received_packet->message_buf, message_buf, message_size);

    return LINK_OK;
}

/**
 * @brief Checks if the expected sender address is the actual sender
 * 
 * @param packet packet 
 * @param expected_sender_address expected address of the sender
 * @return link_ret_t 0 on success, negative on error
 */
static link_ret_t link_check_address(const link_received_packet_t *packet,
                                     uint8_t expected_sender_address) {
    UTIL_ASSERT(packet);

    // Communication can only happen between the AP and a component
    const bool expected_sender_is_ap =
        expected_sender_address == LINK_AP_ADDRESS;
    UTIL_ASSERT(IS_AP != expected_sender_is_ap);

    const bool sender_is_ap = packet->sender_address == LINK_AP_ADDRESS;
    const bool receiver_is_ap = packet->receiver_address == LINK_AP_ADDRESS;

    // Verify that the packet is sent between the AP and a component
    if (sender_is_ap == receiver_is_ap) {
        return LINK_ERR_ADDRESS;  // Invalid sender-receiver pair
    }

    const bool sender_is_expected =
        packet->sender_address == expected_sender_address;
    const bool receiver_is_self = packet->receiver_address == LINK_SELF_ADDRESS;

    if (!receiver_is_self) {  // This board is not the receiver
        if (IS_AP) {
            // The AP can never see a packet to a Component
            return LINK_ERR_ADDRESS;  // Invalid sender-receiver pair
        }
        return LINK_ERR_RECEIVER;
    }

    if (!sender_is_expected) {  // Unexpected sender
        if (!IS_AP) {
            // A Component can never see a packet from another Component
            return LINK_ERR_ADDRESS;  // Invalid sender-receiver pair
        }
        return LINK_ERR_SENDER;
    }

    return LINK_OK;
}

/********** RECEIVE END ***********/

/********** CHECKSUMMING ***********/

/**
 * @brief calculates the checksum for the packet
 * 
 * @param packet_buf packet for which checksum will be calculated
 * @param packet_size size of the packet
 * @return checksum
 */
static uint32_t eval_packet_checksum(const uint8_t *packet_buf,
                                     size_t packet_size) {
    UTIL_ASSERT(packet_buf);
    UTIL_ASSERT(packet_size <= LINK_MAX_PACKET_SIZE);

    const uint8_t *checksumming_buf = packet_buf + LINK_CHECKSUM_SIZE;
    const size_t checksumming_size = packet_size - LINK_CHECKSUM_SIZE;
    return eval_fnv_1a(checksumming_buf, checksumming_size);
}

/**
 * @brief FNV offset basis
 */
#define LINK_FNV_INIT ((uint32_t)0x811c9dc5)   

/**
 * @brief FNV prime
 */
#define LINK_FNV_PRIME ((uint32_t)0x01000193)  


/**
 * @brief Calculates the fnv 1a hash
 * 
 * @param buf buffer
 * @param len length of the buffer
 * @return fnv 1a hash
 */
static uint32_t eval_fnv_1a(const uint8_t *buf, size_t len) {
    UTIL_ASSERT(buf);

    uint32_t hash = LINK_FNV_INIT;
    for (size_t index = 0; index < len; index++) {
        hash ^= (uint32_t)buf[index];
        hash *= LINK_FNV_PRIME;
    }

    return hash;
}

/********** CHECKSUMMING END ***********/

/********** ADDRESSING ***********/

/**
 * @brief I2c reserved address list
 * These address MUST NOT be the address of any component
 */
static const uint8_t reserved_i2c_addresses[] = {
    0b0,        // General call
    0b1,        // CBUS condition
    0b10,       // Reserved for different bus format
    0b11,       // Reserved for future purposes
    0b100,      // Hs-mode
    0b101,      // Hs-mode
    0b110,      // Hs-mode
    0b111,      // Hs-mode
    0b1111000,  // 10-bit addressing
    0b1111001,  // 10-bit addressing
    0b1111010,  // 10-bit addressing
    0b1111011,  // 10-bit addressing
    0b1111100,  // Reserved for future purposes
    0b1111101,  // Reserved for future purposes
    0b1111110,  // Reserved for future purposes
    0b1111111,  // Reserved for future purposes
    0x18,       // Conflicts with on-board I2C peripheral
    0x28,       // Conflicts with on-board I2C peripheral
    0x36,       // Conflicts with on-board I2C peripheral
};

/**
 * @brief Checks whether an I2C address is valid or not
 * 
 * The reserved addresses are as per the I2C specification
 * @param i2c_address 
 * @return true if valid else false
 */
bool is_valid_i2c_address(uint8_t i2c_address) {
    if (i2c_address & ~LINK_I2C_ADDRESS_MASK) {
        return false;  // The most significant bit is not 0
    }

    for (size_t index = 0; index < sizeof(reserved_i2c_addresses); index++) {
        if (i2c_address == reserved_i2c_addresses[index]) {
            return false;  // The address is reserved
        }
    }

    return true;
}

/**
 * @brief Convert component id to i2c address
 * 
 * @param component_id component id
 * @return i2c address
 */
uint8_t component_id_to_i2c_address(uint32_t component_id) {
    return (uint8_t)(component_id & (uint32_t)LINK_I2C_ADDRESS_MASK);
}

/********** ADDRESSING END ***********/
