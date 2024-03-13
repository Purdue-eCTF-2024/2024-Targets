/**
 * @file comm_types.h
 * @author Plaid Parliament of Pwning
 * @brief Message types for communication between AP and component
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include <stdint.h>
#include <assert.h>
#include "attestation_data.h"
#include "crypto_wrappers.h"

// List of packet types
#define COMM_AP_REQ_BOOT_KEY         0x11
#define COMM_COMP_RESP_BOOT_KEY      0x12
#define COMM_AP_REQ_COMP_BOOT        0x13
#define COMM_COMP_RESP_BOOT_MSG      0x14

#define COMM_AP_REQ_AD               0x21
#define COMM_COMP_RESP_AD            0x22

#define COMM_AP_REQ_SECURE_SEND      0x31
#define COMM_COMP_RESP_SECURE_NONCE  0x32
#define COMM_AP_REQ_SECURE_MSG       0x33
#define COMM_COMP_RESP_SECURE_ACK    0x34

#define COMM_AP_REQ_SECURE_RECEIVE   0x41
#define COMM_COMP_RESP_SECURE_MSG    0x42

#define COMM_AP_REQ_LIST_PING        0x51
#define COMM_COMP_RESP_LIST_PONG     0x52

#define COMM_MAX_MSG_LEN 256

#define SEC_LINK_MSG_HDR 0xA6
#define SEC_LINK_ACK_HDR 0xC2

/**
 * @brief Convenience type for a max-length packet.
 */
typedef struct {
    uint8_t data[COMM_MAX_MSG_LEN];
} comm_packet_t;


/**
 * @brief Metadata struct. Must be at the start of every packet.
 */
typedef struct {
	uint32_t msg_type;
} comm_meta_t;


typedef struct {
	comm_meta_t msg_info;
} comm_ap_req_boot_key_t;
static_assert(sizeof(comm_ap_req_boot_key_t) <= COMM_MAX_MSG_LEN, "Message length limit violated");


typedef struct {
	comm_meta_t msg_info;
	uint8_t ap_boot_sub_key[CC_ENC_SYM_KEY_LEN];
} comm_comp_resp_boot_key_t;
static_assert(sizeof(comm_comp_resp_boot_key_t) <= COMM_MAX_MSG_LEN, "Message length limit violated");


typedef struct {
	comm_meta_t msg_info;
	uint8_t comp_boot_sub_key[CC_ENC_SYM_KEY_LEN];
} comm_ap_req_comp_boot_t;
static_assert(sizeof(comm_ap_req_comp_boot_t) <= COMM_MAX_MSG_LEN, "Message length limit violated");


typedef struct {
	comm_meta_t msg_info;
	uint8_t boot_msg[BOOT_MSG_LEN+1];
} comm_comp_resp_boot_msg_t;
static_assert(sizeof(comm_comp_resp_boot_msg_t) <= COMM_MAX_MSG_LEN, "Message length limit violated");


typedef struct {
	comm_meta_t msg_info;
} comm_ap_req_ad_t;
static_assert(sizeof(comm_ap_req_ad_t) <= COMM_MAX_MSG_LEN, "Message length limit violated");


typedef struct {
	comm_meta_t msg_info;
	uint8_t encrypted_att_data[ENCRYPTED_ATT_DATA_LEN];
} comm_comp_resp_ad_t;
static_assert(sizeof(comm_comp_resp_ad_t) <= COMM_MAX_MSG_LEN, "Message length limit violated");


typedef struct {
	comm_meta_t msg_info;
} comm_ap_req_list_ping_t;
static_assert(sizeof(comm_ap_req_list_ping_t) <= COMM_MAX_MSG_LEN, "Message length limit violated");


typedef struct {
	comm_meta_t msg_info;
	uint32_t comp_id;
} comm_comp_resp_list_pong_t;
static_assert(sizeof(comm_comp_resp_list_pong_t) <= COMM_MAX_MSG_LEN, "Message length limit violated");

typedef struct {
    size_t length;
    uint32_t nonce;
    uint8_t header;
    uint8_t src_addr;
    uint8_t dst_addr;
	uint8_t _padding;
    uint8_t data[COMM_MAX_MSG_LEN];
} sec_link_packet_t;

#define SEC_LINK_PACKET_ENC_LEN (sizeof(sec_link_packet_t) + CC_ENC_SYM_METADATA_LEN)

