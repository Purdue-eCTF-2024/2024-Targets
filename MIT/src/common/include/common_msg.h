/**
 * @file "common_msg.h"
 * @brief Common message structs
 */

#ifndef _COMMON_MSG_H_
#define _COMMON_MSG_H_

#include <stdint.h>
#include <stdbool.h>

#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

#define MIT_KEY_SIZE CHACHA20_POLY1305_AEAD_KEYSIZE
#define MIT_NONCE_SIZE CHACHA20_POLY1305_AEAD_IV_SIZE
#define MIT_AUTHTAG_SIZE CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE

#define MIT_CHALLENGE_SIZE 16

#define MIT_MAX_PACKET_LEN 255
#define MIT_MAX_MSG_LEN (MIT_MAX_PACKET_LEN - sizeof(mit_ad_t) - sizeof(mit_authtag_t))

/********** GLOBALS **********/
extern uint8_t null_nonce[MIT_NONCE_SIZE];

/********** DATA TYPES **********/
typedef enum {
    MIT_CMD_NONE,
    MIT_CMD_INIT,
    MIT_CMD_ATTEST,
    MIT_CMD_ATTESTREQ,
    MIT_CMD_BOOT,
    MIT_CMD_BOOTREQ,
    MIT_CMD_POSTBOOT,
} mit_opcode_t;

typedef uint32_t mit_comp_id_t;

typedef union __attribute__((packed)) {
    struct __attribute__((packed)) {
        uint8_t _dummyBytes[MIT_NONCE_SIZE - sizeof(uint32_t)];
        uint32_t sequenceNumber;
    };
    uint8_t rawBytes[MIT_NONCE_SIZE];
} mit_nonce_t;

// Authenticated Data section of packet
typedef union __attribute__((packed)) {
    struct __attribute__((packed)) {
        mit_opcode_t opcode;
        mit_nonce_t nonce;
        mit_comp_id_t comp_id;
        uint8_t len;
        bool for_ap;
    };
    uint8_t rawBytes[sizeof(mit_nonce_t) + sizeof(mit_comp_id_t) + sizeof(mit_opcode_t) + sizeof(uint8_t) + sizeof(bool)];
} mit_ad_t;

// AuthTag section of packet
typedef struct __attribute__((packed)) {
    uint8_t rawBytes[MIT_AUTHTAG_SIZE];
} mit_authtag_t;

// MIT_CMD_INIT packet data
typedef union __attribute__((packed)) {
    struct __attribute__((packed)){
        mit_nonce_t ap_nonce;
        mit_nonce_t component_nonce;
    };
    uint8_t rawBytes[2*sizeof(mit_nonce_t)];
} mit_message_init_t;

// Challenge data type
typedef struct __attribute__((packed)) {
    uint8_t rawBytes[MIT_CHALLENGE_SIZE];
} mit_challenge_t;

// MIT_CMD_ATTESTREQ packet data
typedef union __attribute__((packed)) {
    struct __attribute__((packed)){
        mit_challenge_t r1;
        mit_challenge_t r2;
    };
    uint8_t rawBytes[2*sizeof(mit_challenge_t)];
} mit_message_attestreq_t;

// MIT_CMD_ATTEST packet data
typedef union __attribute__((packed)) {
    mit_challenge_t r2;
    char customerData[MIT_MAX_MSG_LEN];
    uint8_t rawBytes[MIT_MAX_MSG_LEN];
} mit_message_attest_t;

// MIT_CMD_BOOTREQ packet data
typedef union __attribute__((packed)) {
    struct __attribute__((packed)){
        mit_challenge_t r1;
        mit_challenge_t r2;
    };
    uint8_t rawBytes[2*sizeof(mit_challenge_t)];
} mit_message_bootreq_t;

// MIT_CMD_BOOT packet data
typedef union __attribute__((packed)) {
    mit_challenge_t r2;
    char bootMsg[MIT_MAX_MSG_LEN];
    uint8_t rawBytes[MIT_MAX_MSG_LEN];
} mit_message_boot_t;

// Message section of packet
typedef union __attribute__((packed)) {
    uint32_t component_id;
    mit_message_init_t init;
    mit_message_attest_t attest;
    mit_message_attestreq_t attestReq;
    mit_message_boot_t boot;
    mit_message_bootreq_t bootReq;
    uint8_t rawBytes[MIT_MAX_MSG_LEN];
} mit_message_t;

// Entire Packet
typedef union __attribute__((packed)) {
    struct __attribute__((packed)) {
        mit_ad_t ad;
        mit_authtag_t authTag;
        mit_message_t message;
    };
    uint8_t rawBytes[MIT_MAX_PACKET_LEN];
} mit_packet_t;

// Session structure
typedef union __attribute__((packed)) {
    struct __attribute__((packed)) {
        mit_comp_id_t component_id;
        mit_nonce_t outgoing_nonce;
        mit_nonce_t incoming_nonce;
    };
    uint8_t rawBytes[(2*sizeof(mit_nonce_t)) + sizeof(mit_comp_id_t)];
} mit_session_t;

/********** FUNCTIONS **********/
void increment_nonce(mit_nonce_t * nonce, mit_nonce_t * old_nonce);

#endif
