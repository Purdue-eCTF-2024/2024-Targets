/**
 * @file ap_session.c
 * @author MIT TechSec
 * @brief Session-related functions for AP
 * @date 2024
 */

#include "ap_common.h"

static int validate_init_rx_packet(mit_comp_id_t component_id);

mit_session_t sessions[32] = {0};

// Outgoing nonces for sessions are generated at boot.
void session_init(void) {
    delay_rnd;

    // Copy stored component_ids into sessions.
    // Initialize nonce's to {0}.
    for (int i = 0; i < COMPONENT_CNT; i++) {
        delay_rnd;

        sessions[i].component_id = get_component_id(i);

        // Initialize outgoing nonces to some random value
        get_rand_bytes(sessions[i].outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
        get_rand_bytes(sessions[i].outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
        get_rand_bytes(sessions[i].outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    }

    // REDUNDANT
    for (int i = 0; i < COMPONENT_CNT; i++) {
        delay_rnd;

        // Initialize outgoing nonces to some random value
        get_rand_bytes(sessions[i].outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
        get_rand_bytes(sessions[i].outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
        get_rand_bytes(sessions[i].outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    }
}

static int __attribute__((optimize("O0"))) make_mit_init_packet(mit_comp_id_t component_id) {
    delay_rnd;

    int ret;
    mit_nonce_t old_nonce = {0};

    mit_packet_t * packet = get_tx_packet();

    // Check component is provisioned
    mit_session_t * session = get_session_of_component(component_id);

    delay_rnd;

    // REDUNDANT
    if ((session == NULL) ||
        (session == NULL) ||
        (session == NULL)) {
        return ERROR_RETURN;
    }

    // Create init_message buffer
    mit_message_init_t init_msg;
    // REDUNDANT
    memset(init_msg.rawBytes, 0, sizeof(mit_message_init_t));
    memset(init_msg.rawBytes, 0, sizeof(mit_message_init_t));
    memset(init_msg.rawBytes, 0, sizeof(mit_message_init_t));

    delay_rnd;

    // Copy outgoing nonce into first field
    // REDUNDANT
    memcpy(init_msg.ap_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(init_msg.ap_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(init_msg.ap_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    // REDUNDANT
    if ((mit_ConstantCompare_nonce(session->outgoing_nonce.rawBytes, init_msg.ap_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(session->outgoing_nonce.rawBytes, init_msg.ap_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(session->outgoing_nonce.rawBytes, init_msg.ap_nonce.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Set authData field
    // REDUNDANT
    packet->ad.comp_id = component_id;
    packet->ad.opcode = MIT_CMD_INIT;
    packet->ad.len = sizeof(mit_message_init_t);
    packet->ad.for_ap = false;
    memcpy(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(packet->ad.nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    // Encrypt init_msg into packet, generate authTag
    ret = mit_encrypt(packet, init_msg.rawBytes, sizeof(mit_message_init_t));

    delay_rnd;

    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    delay_rnd;

    memcpy(old_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    if (mit_ConstantCompare_nonce(session->outgoing_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(packet, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    delay_rnd;

    increment_nonce(&session->outgoing_nonce, &old_nonce);
    increment_nonce(&session->outgoing_nonce, &old_nonce);
    increment_nonce(&session->outgoing_nonce, &old_nonce);
    /***********************/

    return SUCCESS_RETURN;
}

static int issue_init_cmd(mit_comp_id_t component_id) {
    delay_rnd;

    int ret, len;
    mit_packet_t * rx_packet = get_rx_packet();
    mit_packet_t * tx_packet = get_tx_packet();

    i2c_addr_t addr = component_id_to_i2c_addr((uint32_t)component_id);

    // Validate current tx packet belongs to component id
    if (tx_packet->ad.comp_id != component_id) {
        return ERROR_RETURN;
    }

    // Send packet to the wire
    ret = send_mit_packet(addr, tx_packet);
    if (ret == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Receive a message
    // REDUNDANT
    memset(rx_packet, 0, sizeof(mit_packet_t));
    memset(rx_packet, 0, sizeof(mit_packet_t));
    memset(rx_packet, 0, sizeof(mit_packet_t));
    len = poll_and_receive_packet(addr, rx_packet);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Validate authData section
    // REDUNDANT
    if ((validate_init_rx_packet(component_id) != SUCCESS_RETURN) ||
        (validate_init_rx_packet(component_id) != SUCCESS_RETURN) ||
        (validate_init_rx_packet(component_id) != SUCCESS_RETURN)) {
        memset(rx_packet, 0, sizeof(mit_packet_t));
        memset(rx_packet, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    delay_rnd;

    // REDUNDANT
    memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
    memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
    memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);

    ret = mit_decrypt(rx_packet, ap_plaintext);

    delay_rnd;

    if (ret != SUCCESS_RETURN) {
        memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}

// Ensures that we have an active session with a given component_id
// If not, we establish one.
int __attribute__((optimize("O0"))) validate_session(mit_comp_id_t component_id) {
    delay_rnd;

    int ret = ERROR_RETURN;
    mit_nonce_t old_nonce = {0};

    // Find session ptr
    mit_session_t * session = get_session_of_component(component_id);
    if ((session == NULL) ||
        (session == NULL) ||
        (session == NULL)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // If incoming_nonce is set, we have established a session already
    // REDUNDANT
    ret =  mit_ConstantCompare_nonce(session->incoming_nonce.rawBytes, null_nonce);
    if ((ret != 0) && (ret != 0) && (ret != 0)) {
        return SUCCESS_RETURN;
    }

    delay_rnd;

    /**** Create new session ****/

    // Save expected nonce in response message
    mit_nonce_t expected_nonce;
    // REDUNDANT
    memcpy(expected_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(expected_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(expected_nonce.rawBytes, session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    // Construct packet
    ret = make_mit_init_packet(component_id);
    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Issue command
    ret = issue_init_cmd(component_id);
    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Validation
    mit_packet_t * packet = get_rx_packet();
    mit_message_init_t * received = (mit_message_init_t *)ap_plaintext;

    delay_rnd;

    // Validate nonce in message corresponds to nonce in authData
    // REDUNDANT
    if ((mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, received->component_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, received->component_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, received->component_nonce.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Validate ap_nonce in message corresponds to ap_nonce we sent
    // REDUNDANT
    if ((mit_ConstantCompare_nonce(received->ap_nonce.rawBytes, expected_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(received->ap_nonce.rawBytes, expected_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(received->ap_nonce.rawBytes, expected_nonce.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Validate received nonce isn't 0 :-)
    // REDUNDANT
    if ((mit_ConstantCompare_nonce(received->component_nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(received->component_nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(received->component_nonce.rawBytes, null_nonce) == 0)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Save incoming nonce, cross fingers we did everything right.
    // REDUNDANT
    memcpy(session->incoming_nonce.rawBytes, received->component_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(session->incoming_nonce.rawBytes, received->component_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(session->incoming_nonce.rawBytes, received->component_nonce.rawBytes, sizeof(mit_nonce_t));

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    delay_rnd;

    memcpy(old_nonce.rawBytes, session->incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session->incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session->incoming_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    if (mit_ConstantCompare_nonce(session->incoming_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(packet, 0, sizeof(mit_packet_t));
        memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
        return ERROR_RETURN;
    }

    delay_rnd;

    increment_nonce(&session->incoming_nonce, &old_nonce);
    increment_nonce(&session->incoming_nonce, &old_nonce);
    increment_nonce(&session->incoming_nonce, &old_nonce);
    /***********************/

    return SUCCESS_RETURN;
}

// Get ptr to session of given component_id
mit_session_t * get_session_of_component(mit_comp_id_t component_id) {
    delay_rnd;

    for (int i = 0; i < COMPONENT_CNT; i++) {
        if (sessions[i].component_id == component_id) {
            return &sessions[i];
        }
    }

    return NULL;
}

// Validate packet in the received buffer
static int __attribute__((optimize("O0"))) validate_init_rx_packet(mit_comp_id_t component_id) {
    delay_rnd;

    mit_packet_t * rx_packet = get_rx_packet();

    // Check authenticated data fields

    delay_rnd;

    // REDUNDANT
    if ((rx_packet->ad.comp_id != component_id) ||
        (rx_packet->ad.comp_id != component_id) ||
        (rx_packet->ad.comp_id != component_id)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // REDUNDANT
    if ((rx_packet->ad.for_ap != true) ||
        (rx_packet->ad.for_ap != true) ||
        (rx_packet->ad.for_ap != true)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // REDUNDANT
    if ((rx_packet->ad.len != sizeof(mit_message_init_t)) ||
        (rx_packet->ad.len != sizeof(mit_message_init_t)) ||
        (rx_packet->ad.len != sizeof(mit_message_init_t))) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // REDUNDANT
    if ((rx_packet->ad.opcode != MIT_CMD_INIT) ||
        (rx_packet->ad.opcode != MIT_CMD_INIT) ||
        (rx_packet->ad.opcode != MIT_CMD_INIT)) {
        return ERROR_RETURN;        
    }

    delay_rnd;

    // REDUNDANT
    if ((mit_ConstantCompare_nonce(rx_packet->ad.nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(rx_packet->ad.nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(rx_packet->ad.nonce.rawBytes, null_nonce) == 0)) {
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}
