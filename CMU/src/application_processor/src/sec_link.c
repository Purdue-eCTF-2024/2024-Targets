/**
 * @file sec_link.c
 * @author Plaid Parliament of Pwning
 * @brief Functions for secure wrapper over link layer
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include "comm_link_ap.h"
#include "comm_link.h"
#include "rng.h"
#include "sec_link.h"
#include "comm_types.h"
#include "keys.h"
#include "util.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "monocypher.h"
#include "host_messaging.h"
#include "fiproc.h"

// Provide (very limited) resistance against replays
uint32_t last_nonce = 0;

/**
 * @brief Initialize the secure link layer
 * 
 * Always succeeds.
 */
int sec_link_init(void) {
    link_init();
    return SUCCESS_RETURN;
}

/**
 * @brief Adds a layer of encryption over the link layer
 * 
 * @param send_buf buffer to send
 * @param len length of buffer
 * @param unenforced_i2c_addr receiver's address
 * @param ack_timeout_ms timeout in milliseconds for ack
 * @return 0 on success, negative on error
 */
int sec_link_send_and_wait_ack(uint8_t *send_buf, size_t len, uint8_t unenforced_i2c_addr, int32_t ack_timeout_ms) {
    // HCF: Getting invalid arguments from the client code
    // should not be possible unless there is hardware fault
    if (!send_buf) {
        HALT_AND_CATCH_FIRE();
    }
    if (len > COMM_MAX_MSG_LEN) {
        HALT_AND_CATCH_FIRE();
    }

    sec_link_packet_t packet;

    // Pre-gen some randomness - generate both the replay nonce and the encryption nonce
    uint8_t rng_bytes[CC_NONCE_RAND_LEN + sizeof(packet.nonce)];
    rng_generate_bulk_fast(rng_bytes, sizeof(rng_bytes));

    FIPROC_DELAY_WRAP();
    // (1) Construct the packet
    packet.header = SEC_LINK_MSG_HDR;
    packet.src_addr = LINK_AP_ADDRESS;
    packet.dst_addr = unenforced_i2c_addr;
    packet.length = len;
    SECURE_MEMCPY(&(packet.nonce), rng_bytes+CC_NONCE_RAND_LEN, sizeof(packet.nonce));
    last_nonce = packet.nonce;
    crypto_wipe(packet.data, sizeof(packet.data));
    FIPROC_DELAY_WRAP();
    SECURE_MEMCPY(packet.data, send_buf, len);

    // (2) Encrypt the packet
    uint8_t packet_encrypted[SEC_LINK_PACKET_ENC_LEN];
    FIPROC_DELAY_WRAP();
    cc_encrypt_symmetric(packet_encrypted, (uint8_t*)&packet, sizeof(packet), DEPLOYMENT_KEY, rng_bytes);
    crypto_wipe(&packet, sizeof(packet));

    FIPROC_DELAY_WRAP();

    // (3) Send the encrypted packet
    if (link_send_and_wait_ack(packet_encrypted, SEC_LINK_PACKET_ENC_LEN,
                unenforced_i2c_addr, ack_timeout_ms) != LINK_OK) {
        return ERROR_RETURN;
    }

    crypto_wipe(packet_encrypted, sizeof(packet_encrypted));

    return SUCCESS_RETURN;
}

/**
 * @brief Adds a layer of encryption over the link layer
 * 
 * @param receive_buf buffer to receive data into
 * @param max_len max len of the data that can be received
 * @param unenforced_i2c_addr expected address of the sender
 * @return int32_t packet size if positive, negative on error
 */
int32_t sec_link_receive(uint8_t *receive_buf, size_t max_len, uint8_t unenforced_i2c_addr) {
    // HCF: Getting invalid arguments from the client code
    // should not be possible unless there is hardware fault
    if (!receive_buf) {
        HALT_AND_CATCH_FIRE();
    }
    if (max_len > COMM_MAX_MSG_LEN) {
        HALT_AND_CATCH_FIRE();
    }

    // (1) Receive the encrypted packet
    uint8_t packet_encrypted[SEC_LINK_PACKET_ENC_LEN];

    if (link_receive(packet_encrypted, SEC_LINK_PACKET_ENC_LEN, unenforced_i2c_addr) != SEC_LINK_PACKET_ENC_LEN) {
        return ERROR_RETURN;
    }

    // (2) Decrypt the packet
    FIPROC_DELAY_WRAP();
    sec_link_packet_t packet;
    if (cc_decrypt_symmetric((uint8_t*)&packet, packet_encrypted, sizeof(packet), DEPLOYMENT_KEY)) {
        return ERROR_RETURN;
    }
    FIPROC_DELAY_WRAP();
    crypto_wipe(packet_encrypted, sizeof(packet_encrypted));

    // (3) Validate the packet
    if (packet.header != SEC_LINK_MSG_HDR) {
        return ERROR_RETURN;
    }

    if (packet.src_addr != unenforced_i2c_addr) {
        return ERROR_RETURN;
    }

    if (packet.dst_addr != LINK_AP_ADDRESS) {
        return ERROR_RETURN;
    }

    if (packet.length != max_len) {
        return ERROR_RETURN;
    }

    if (last_nonce != packet.nonce) {
        return ERROR_RETURN;
    }

    FIPROC_DELAY_WRAP();
    SECURE_MEMCPY(receive_buf, packet.data, packet.length);

    size_t ret = packet.length;

    crypto_wipe(&packet, sizeof(packet));

    return ret;
}

/**
 * @brief Check for a device's existence by sending it a 0-len packet
 * 
 * Note that this will get picked up by whatever receive call is on the
 * other device. This is fine since sec_link will note the length is
 * wrong and immediately discard it.
 * 
 * @param unenforced_i2c_addr receiver's i2c address
 * @param ack_timeout_ms timeout in milliseconds
 * @return 0 on success, negative on error
 */
int sec_link_poll(uint8_t unenforced_i2c_addr, int32_t ack_timeout_ms) {
    // Send a 0-length packet. This will fail in SLL on component side
    // but that is a silent failure and happens _after_ ACKing
    const link_ret_t ret = link_send_and_wait_ack(&unenforced_i2c_addr, 0, unenforced_i2c_addr, ack_timeout_ms);
    if (ret != LINK_OK) {
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}
