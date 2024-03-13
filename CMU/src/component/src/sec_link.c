/**
 * @file sec_link.c
 * @author Plaid Parliament of Pwning
 * @brief Functions for crypto wrapper over link layer
 * 
 * Provides resistance against replays.
 * 
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include "comm_link_component.h"
#include "comm_link.h"
#include "rng.h"
#include "sec_link.h"
#include "comm_types.h"
#include "resources.h"
#include "util.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "monocypher.h"
#include "fiproc.h"

#define SEC_LINK_SELF_ADDR (((uint8_t)COMPONENT_ID) & 0x7f)

/**
 * @brief Last nonce used
 */
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
 * @param len length of the buffer
 * @return 0 on success, negative on error
 */
int sec_link_respond(uint8_t *send_buf, size_t len) {
    // HCF: Getting invalid arguments from the client code
    // should not be possible unless there is hardware fault
    if (!send_buf) {
        HALT_AND_CATCH_FIRE();
    }
    if (len > COMM_MAX_MSG_LEN) {
        HALT_AND_CATCH_FIRE();
    }

    // Pre-gen some randomness
    uint8_t rng_bytes[32];
    FIPROC_DELAY_WRAP();
    rng_generate_bulk_fast(rng_bytes, sizeof(rng_bytes));

    // (1) Construct the packet
    sec_link_packet_t packet;
    packet.header = SEC_LINK_MSG_HDR;
    packet.src_addr = SEC_LINK_SELF_ADDR;
    packet.dst_addr = LINK_AP_ADDRESS;
    packet.length = len;
    packet.nonce = last_nonce;
    crypto_wipe(packet.data, sizeof(packet.data));
    SECURE_MEMCPY(packet.data, send_buf, len);

    // (2) Encrypt the packet
    uint8_t packet_encrypted[SEC_LINK_PACKET_ENC_LEN];
    FIPROC_DELAY_WRAP();
    cc_encrypt_symmetric(packet_encrypted, (uint8_t*)&packet, sizeof(packet), DEPLOYMENT_KEY, rng_bytes);

    crypto_wipe(&packet, sizeof(packet));
    crypto_wipe(rng_bytes, sizeof(rng_bytes));

    // (3) Send the encrypted packet
    if (link_respond(packet_encrypted, SEC_LINK_PACKET_ENC_LEN) != LINK_OK) {
        return ERROR_RETURN;
    }

    crypto_wipe(packet_encrypted, sizeof(packet_encrypted));

    return SUCCESS_RETURN;
}

/**
 * @brief Adds a layer of encryption over the link layer
 * 
 * @param receive_buf receive buffer
 * @param max_len length of the receive buffer in bytes
 * @return int64_t actual length of the data received if positive, negative on error
 */
int64_t sec_link_receive_and_send_ack(uint8_t *receive_buf, size_t max_len) {
    // HCF: Getting invalid arguments from the client code
    // should not be possible unless there is hardware fault
    if (!receive_buf) {
        HALT_AND_CATCH_FIRE();
    }

    if (max_len > COMM_MAX_MSG_LEN) {
        HALT_AND_CATCH_FIRE();
    }

    // (1) Receive the encrypted packet
    // this buffer needs to be extra big due to I2C link quirk
    uint8_t packet_encrypted[SEC_LINK_PACKET_ENC_LEN];

    if (link_receive_and_send_ack(packet_encrypted, SEC_LINK_PACKET_ENC_LEN) != SEC_LINK_PACKET_ENC_LEN) {
        return ERROR_RETURN;
    }

    // (2) Decrypt the packet
    sec_link_packet_t packet;
    crypto_wipe(&packet, sizeof(packet));

    FIPROC_DELAY_WRAP();
    if (cc_decrypt_symmetric((uint8_t*)&packet, packet_encrypted, sizeof(packet), DEPLOYMENT_KEY)) {
        return ERROR_RETURN;
    }
    FIPROC_DELAY_WRAP();
    crypto_wipe(packet_encrypted, sizeof(packet_encrypted));

    // (3) Validate the packet
    if (packet.header != SEC_LINK_MSG_HDR) {
        return ERROR_RETURN;
    }

    if (packet.src_addr != LINK_AP_ADDRESS) {
        return ERROR_RETURN;
    }

    if (packet.dst_addr != SEC_LINK_SELF_ADDR) {
        return ERROR_RETURN;
    }

    if (packet.length != max_len) {
        return ERROR_RETURN;
    }

    last_nonce = packet.nonce;

    FIPROC_DELAY_WRAP();

    SECURE_MEMCPY(receive_buf, packet.data, packet.length);

    size_t ret = packet.length;

    crypto_wipe(&packet, sizeof(packet));

    return ret;
}
