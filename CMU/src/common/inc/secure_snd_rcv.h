/**
 * @file secure_snd_rcv.h
 * @author Plaid Parliament of Pwning
 * @brief Structs and prototypes for Secure Send and Receive
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include <stdint.h>

// Message types
#define COMM_AP_REQ_SECURE_SEND      0x31
#define COMM_COMP_RESP_SECURE_NONCE  0x32
#define COMM_AP_REQ_SECURE_MSG       0x33
#define COMM_COMP_RESP_SECURE_ACK    0x34

#define AP_ID 0xFF

// Maximum message length
#define MAX_MSG_LEN (64) 

/**
 * @brief Time to delay on retry in microseconds
 */
#define RETRY_DELAY_TX 50000
#define RETRY_DELAY_RX 12000

#define FAILED(status) (((int)(status)) != SUCCESS_RETURN)

/**
 * @brief Secure message sent between AP and component
 */
typedef struct{
    uint32_t message_len;
    uint32_t seq_num;
    uint32_t nonce;
    uint8_t message_type;
    uint8_t sender_id;
    uint8_t receiver_id;
    uint8_t message[MAX_MSG_LEN]; 
} secure_msg_t;
