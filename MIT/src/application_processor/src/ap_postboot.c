/**
 * @file ap_postboot.c
 * @author MIT TechSec
 * @brief Post-Boot-related functions for AP
 * @date 2024
 */

#include "ap_common.h"

/**
 * @brief Secure Send 
 * 
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.

*/
int __attribute__((optimize("O0"))) secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    delay_rnd;

    int ret = ERROR_RETURN;
    mit_comp_id_t component_id = ERROR_RETURN;
    mit_packet_t * tx_packet = get_tx_packet();

    memset(tx_packet, 0, sizeof(mit_packet_t));
    memset(tx_packet, 0, sizeof(mit_packet_t));
    memset(tx_packet, 0, sizeof(mit_packet_t));

    delay_rnd;

    for (int id = 0; id < COMPONENT_CNT; id++) {
        delay_rnd;

        if (component_id_to_i2c_addr(get_component_id(id)) == address) {
            component_id = get_component_id(id);
        }
    }

    if (component_id == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    delay_rnd;

    ret = make_mit_packet(component_id, MIT_CMD_POSTBOOT, buffer, len);
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ret;
    }

    return send_mit_packet(address, tx_packet);
}

/**
 * @brief Secure Receive
 * 
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int __attribute__((optimize("O0"))) secure_receive(i2c_addr_t address, uint8_t* buffer) {
    delay_rnd;

    int ret, len;
    mit_packet_t * packet = get_rx_packet();
    mit_nonce_t old_nonce = {0};
    mit_comp_id_t component_id = ERROR_RETURN;

    for (int id = 0; id < COMPONENT_CNT; id++) {
        delay_rnd;

        if (component_id_to_i2c_addr(get_component_id(id)) == address) {
            component_id = get_component_id(id);
        }
    }

    if (component_id == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    delay_rnd;

    mit_session_t * session = get_session_of_component(component_id);
    if ((session == NULL) ||
        (session == NULL) ||
        (session == NULL)) {
        print_error("Session not found for component id 0x%08x\n", component_id);
    }

    memset(buffer, 0, 64);
    memset(packet, 0, sizeof(mit_packet_t));

    delay_rnd;

    len = poll_and_receive_packet(address, packet);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
   /*************** VALIDATE RECEIVED PACKET ****************/

    delay_rnd;

    // REDUNDANT
    if ((validate_rx_packet(component_id, MIT_CMD_POSTBOOT) != SUCCESS_RETURN) ||
        (validate_rx_packet(component_id, MIT_CMD_POSTBOOT) != SUCCESS_RETURN) ||
        (validate_rx_packet(component_id, MIT_CMD_POSTBOOT) != SUCCESS_RETURN)) {
        memset(packet, 0, sizeof(mit_packet_t));
        memset(packet, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    // OK, we can go ahead and decrypt now. Hopefully all those redundant checks served us well!

    delay_rnd;

    // REDUNDANT
    memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
    memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
    memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);

    delay_rnd;

    ret = mit_decrypt(packet, ap_plaintext);

    delay_rnd;

    // REDUNDANT
    if ((ret != 0) ||
        (ret != 0) ||
        (ret != 0)) {
        // REDUNDANT
        memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
        memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
        memset(ap_plaintext, 0, AP_PLAINTEXT_LEN);
        return ERROR_RETURN;
    }

    delay_rnd;

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

    /********************************************************/
    memcpy(buffer, ap_plaintext, len);

    return len;
}

/**
 * @brief Get Provisioned IDs
 * 
 * @param uint32_t* buffer
 * 
 * @return int: number of ids
 * 
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT functionality.
 * This function must be implemented by your team.
*/
int get_provisioned_ids(uint32_t* buffer) {
    delay_rnd;

    for (int id = 0; id < COMPONENT_CNT; id++) {
        buffer[id] = get_component_id(id);
    }
    return COMPONENT_CNT;
}
