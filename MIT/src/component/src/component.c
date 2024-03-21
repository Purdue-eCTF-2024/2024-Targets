/**
 * @file component.c
 * @author MIT TechSec
 * @brief eCTF Component Implementation
 * @date 2024
 */

#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "simple_i2c_peripheral.h"
#include "board_link.h"

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

// MIT: Includes for our custom features
#include "common_crypto.h"
#include "common_delay.h"
#include "common_init.h"
#include "common_msg.h"
#include "simple_trng.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
int component_process_cmd(void);
int process_boot(void);
int process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

#define COMP_PLAINTEXT_LEN 256
uint8_t comp_plaintext[COMP_PLAINTEXT_LEN];

mit_session_t session = {0};

/******************************* MIT UTILITIES ********************************/

void session_init(void) {
    // REDUNDANT
    get_rand_bytes(session.outgoing_nonce.rawBytes, MIT_NONCE_SIZE);
    get_rand_bytes(session.outgoing_nonce.rawBytes, MIT_NONCE_SIZE);
    get_rand_bytes(session.outgoing_nonce.rawBytes, MIT_NONCE_SIZE);
}

bool valid_session(void) {
    return mit_ConstantCompare_nonce(session.incoming_nonce.rawBytes, null_nonce) != 0;
}

int __attribute__((optimize("O0"))) validate_packet(mit_opcode_t expected_opcode) {
    delay_rnd;

    mit_packet_t * rx_packet = (mit_packet_t *) receive_buffer;

    // REDUNDANT
    if ((rx_packet->ad.comp_id != COMPONENT_ID) ||
        (rx_packet->ad.comp_id != COMPONENT_ID) ||
        (rx_packet->ad.comp_id != COMPONENT_ID)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // REDUNDANT
    if ((rx_packet->ad.for_ap != false) ||
        (rx_packet->ad.for_ap != false) ||
        (rx_packet->ad.for_ap != false)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // REDUNDANT
    if ((rx_packet->ad.len > MIT_MAX_MSG_LEN) ||
        (rx_packet->ad.len > MIT_MAX_MSG_LEN) ||
        (rx_packet->ad.len > MIT_MAX_MSG_LEN)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // REDUNDANT
    if ((rx_packet->ad.opcode != expected_opcode) ||
        (rx_packet->ad.opcode != expected_opcode) ||
        (rx_packet->ad.opcode != expected_opcode)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Just check again we have a valid session :)
    // REDUNDANT
    if (!valid_session() || !valid_session() || !valid_session()) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Check received nonce matches expected nonce
    // REDUNDANT
    if ((mit_ConstantCompare_nonce(rx_packet->ad.nonce.rawBytes, session.incoming_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(rx_packet->ad.nonce.rawBytes, session.incoming_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(rx_packet->ad.nonce.rawBytes, session.incoming_nonce.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}

// Like above, but we don't check for opcode
int __attribute__((optimize("O0"))) validate_any_packet(void) {
    delay_rnd;

    mit_packet_t * rx_packet = (mit_packet_t *) receive_buffer;

    // REDUNDANT
    if ((rx_packet->ad.comp_id != COMPONENT_ID) ||
        (rx_packet->ad.comp_id != COMPONENT_ID) ||
        (rx_packet->ad.comp_id != COMPONENT_ID)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // REDUNDANT
    if ((rx_packet->ad.for_ap != false) ||
        (rx_packet->ad.for_ap != false) ||
        (rx_packet->ad.for_ap != false)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // REDUNDANT
    if ((rx_packet->ad.len > MIT_MAX_MSG_LEN) ||
        (rx_packet->ad.len > MIT_MAX_MSG_LEN) ||
        (rx_packet->ad.len > MIT_MAX_MSG_LEN)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Just check again we have a valid session :)
    // REDUNDANT
    if (!valid_session() || !valid_session() || !valid_session()) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Check received nonce matches expected nonce
    // REDUNDANT
    if ((mit_ConstantCompare_nonce(rx_packet->ad.nonce.rawBytes, session.incoming_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(rx_packet->ad.nonce.rawBytes, session.incoming_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(rx_packet->ad.nonce.rawBytes, session.incoming_nonce.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}

void set_ad(mit_packet_t * packet, mit_comp_id_t comp_id, mit_opcode_t opcode, uint8_t len) {
    packet->ad.comp_id = comp_id;
    packet->ad.opcode = opcode;
    packet->ad.len = len;
    packet->ad.for_ap = true;
}

/**
 * @brief Helper for constructing packets
 * 
 * @param component_id: mit_comp_id_t, id of component to make packet for
 * @param opcode: mit_opcode_t, opcode to make packet for
 * @param data: uint8_t *, ptr for data to store in message ield
 * @param len: uint8_t, len of data to copy into message field
 */
int __attribute__((optimize("O0"))) make_mit_packet(mit_comp_id_t component_id, mit_opcode_t opcode, uint8_t * data, uint8_t len) {
    delay_rnd;

    int ret = ERROR_RETURN;
    mit_nonce_t old_nonce = {0};

    mit_packet_t * packet = (mit_packet_t *)transmit_buffer;

    // Clear tx buffer
    // REDUNDANT
    memset(packet, 0, sizeof(mit_packet_t));
    memset(packet, 0, sizeof(mit_packet_t));
    memset(packet, 0, sizeof(mit_packet_t));

    // Set Authenticated Data field
    set_ad(packet, component_id, opcode, len);

    /***** NONCE GENERATION/LOOKUP *****/

    delay_rnd;

    // if the nonce is 0, abort
    if ((mit_ConstantCompare_nonce(session.outgoing_nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(session.outgoing_nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(session.outgoing_nonce.rawBytes, null_nonce) == 0)) {
        return ERROR_RETURN;
    }

    // REDUNDANT
    memcpy(packet->ad.nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(packet->ad.nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(packet->ad.nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    // Confirm we actually copied
    // REDUNDANT
    if ((mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, session.outgoing_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, session.outgoing_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, session.outgoing_nonce.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    /****************************/

    // Encrypt in data
    ret = mit_encrypt(packet, data, len);
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        memset(packet, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    delay_rnd;

    memcpy(old_nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    if (mit_ConstantCompare_nonce(session.outgoing_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(transmit_buffer, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    delay_rnd;

    increment_nonce(&session.outgoing_nonce, &old_nonce);
    increment_nonce(&session.outgoing_nonce, &old_nonce);
    increment_nonce(&session.outgoing_nonce, &old_nonce);
    /***********************/

    return SUCCESS_RETURN;
}

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
void secure_send(uint8_t* buffer, uint8_t len) {
    delay_rnd;

    memset(transmit_buffer, 0, sizeof(mit_packet_t));
    memset(transmit_buffer, 0, sizeof(mit_packet_t));
    memset(transmit_buffer, 0, sizeof(mit_packet_t));

    if (!make_mit_packet(COMPONENT_ID, MIT_CMD_POSTBOOT, buffer, len)) {
        send_packet_and_ack((mit_packet_t *)transmit_buffer);
    }
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int __attribute__((optimize("O0"))) secure_receive(uint8_t* buffer) {
    delay_rnd;

    int ret = ERROR_RETURN;
    mit_packet_t * packet = (mit_packet_t *) receive_buffer;
    mit_nonce_t old_nonce = {0};

    memset(buffer, 0, 64);
    memset(buffer, 0, 64);
    memset(buffer, 0, 64);

    uint8_t len = wait_and_receive_packet(packet);

   /*************** VALIDATE RECEIVED PACKET ****************/

   delay_rnd;

    // REDUNDANT
    if ((validate_packet(MIT_CMD_POSTBOOT) != SUCCESS_RETURN) ||
        (validate_packet(MIT_CMD_POSTBOOT) != SUCCESS_RETURN) ||
        (validate_packet(MIT_CMD_POSTBOOT) != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    ret = mit_decrypt(packet, comp_plaintext);
    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    delay_rnd;

    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    if (mit_ConstantCompare_nonce(session.incoming_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(receive_buffer, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    delay_rnd;

    increment_nonce(&session.incoming_nonce, &old_nonce);
    increment_nonce(&session.incoming_nonce, &old_nonce);
    increment_nonce(&session.incoming_nonce, &old_nonce);
    /***********************/

    /********************************************************/
    memcpy(buffer, comp_plaintext, len);

    return len;
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
}

// Handle a transaction from the AP
int __attribute__((optimize("O0"))) component_process_cmd() {
    delay_rnd;

    int ret = ERROR_RETURN;
    mit_packet_t * packet = (mit_packet_t *) receive_buffer;

    // Can't hurt to check, just once more.
    // REDUNDANT
    if (!valid_session() || !valid_session() || !valid_session()) {
        return ERROR_RETURN;
    }

    delay_rnd;

    /*************** VALIDATE RECEIVED PACKET ****************/
    if ((validate_any_packet() != SUCCESS_RETURN) ||
        (validate_any_packet() != SUCCESS_RETURN) ||
        (validate_any_packet() != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    // Clear plaintext buffer
    // REDUNDANT
    memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);
    memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);
    memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);

    delay_rnd;

    // Validate integrity of packet
    ret = mit_decrypt(packet, comp_plaintext);

    delay_rnd;

    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);
        return ERROR_RETURN;
    }

    delay_rnd;

    // Clear plaintext buffer, we decrypt again inside process_*
    // REDUNDANT
    memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);
    memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);
    memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);

    delay_rnd;

    // Output to application processor dependent on command received
    switch (packet->ad.opcode) {
    case MIT_CMD_BOOTREQ:
        ret = process_boot();
        break;
    case MIT_CMD_ATTESTREQ:
        ret = process_attest();
        break;
    default:
        ret = ERROR_RETURN;
    }

    // Clear plaintext buffer & receive buffer
    // REDUNDANT
    memset(packet, 0, sizeof(mit_packet_t));
    memset(packet, 0, sizeof(mit_packet_t));
    memset(packet, 0, sizeof(mit_packet_t));
    // REDUNDANT
    memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);
    memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);
    memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);

    return ret;
}

int __attribute__((optimize("O0"))) process_boot() {
    delay_rnd;

    int ret = ERROR_RETURN;
    uint8_t len;
    mit_challenge_t r1, r2;
    mit_message_t * message = (mit_message_t *)comp_plaintext;
    mit_nonce_t old_nonce = {0};

    mit_packet_t * packet = (mit_packet_t *) receive_buffer;

    // Step 0: validate packet again :-)
    // REDUNDANT
    if ((validate_packet(MIT_CMD_BOOTREQ) != SUCCESS_RETURN) ||
        (validate_packet(MIT_CMD_BOOTREQ) != SUCCESS_RETURN) ||
        (validate_packet(MIT_CMD_BOOTREQ) != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    ret = mit_decrypt(packet, comp_plaintext);
    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    delay_rnd;

    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    if (mit_ConstantCompare_nonce(session.incoming_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(receive_buffer, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    delay_rnd;

    increment_nonce(&session.incoming_nonce, &old_nonce);
    increment_nonce(&session.incoming_nonce, &old_nonce);
    increment_nonce(&session.incoming_nonce, &old_nonce);
    /***********************/

    delay_rnd;

    // Step 1: Generate random challenge r2
    // REDUNDANT
    get_random_challenge(&r2);
    get_random_challenge(&r2);
    get_random_challenge(&r2);

    // Step 2: Store r2 in response packet
    // REDUNDANT
    memcpy(message->bootReq.r2.rawBytes, r2.rawBytes, sizeof(mit_challenge_t));
    memcpy(message->bootReq.r2.rawBytes, r2.rawBytes, sizeof(mit_challenge_t));
    memcpy(message->bootReq.r2.rawBytes, r2.rawBytes, sizeof(mit_challenge_t));

    delay_rnd;

    // Step 3: Send response packet
    ret = make_mit_packet(COMPONENT_ID, MIT_CMD_BOOTREQ, message->bootReq.rawBytes, sizeof(mit_message_bootreq_t));
    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ret;
    }

    send_packet_and_ack((mit_packet_t *)transmit_buffer);

    // Step 4: Wait to receive a packet
    len = wait_and_receive_packet(receive_buffer);
    if (len <= sizeof(mit_comp_id_t)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Step 5: Validate packet
    // REDUNDANT
    if ((validate_packet(MIT_CMD_BOOT) != SUCCESS_RETURN) ||
        (validate_packet(MIT_CMD_BOOT) != SUCCESS_RETURN) ||
        (validate_packet(MIT_CMD_BOOT) != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    ret = mit_decrypt(packet, comp_plaintext);
    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    delay_rnd;

    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    if (mit_ConstantCompare_nonce(session.incoming_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(receive_buffer, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    delay_rnd;

    increment_nonce(&session.incoming_nonce, &old_nonce);
    increment_nonce(&session.incoming_nonce, &old_nonce);
    increment_nonce(&session.incoming_nonce, &old_nonce);
    /***********************/

    // Step 6: Validate r2 in attest response
    // REDUNDANT
    if ((mit_ConstantCompare_challenge(message->boot.r2.rawBytes, r2.rawBytes) != 0) ||
        (mit_ConstantCompare_challenge(message->boot.r2.rawBytes, r2.rawBytes) != 0) ||
        (mit_ConstantCompare_challenge(message->boot.r2.rawBytes, r2.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Step 7: Stuff with boot message
    memset(message->boot.rawBytes, 0, sizeof(mit_message_boot_t));
    len = sprintf(message->boot.bootMsg, "%s", COMPONENT_BOOT_MSG) + 1;

    ret = make_mit_packet(COMPONENT_ID, MIT_CMD_BOOT, message->boot.rawBytes, sizeof(mit_message_boot_t));
    if (ret != SUCCESS_RETURN) {
        return ret;
    }

    send_packet_and_ack((mit_packet_t *)transmit_buffer);
    // Call the boot function
    boot();

    // We should never reach this.
    return ERROR_RETURN;
}

int __attribute__((optimize("O0"))) process_attest() {
    delay_rnd;

    int ret = ERROR_RETURN;
    uint8_t len;
    mit_challenge_t r1, r2;
    mit_message_attest_t * attest = (mit_message_attest_t *)comp_plaintext;
    mit_message_attestreq_t * attestReq = (mit_message_attestreq_t *)comp_plaintext;
    mit_nonce_t old_nonce = {0};

    mit_packet_t * packet = (mit_packet_t *) receive_buffer;

    // Step 0: validate packet again :-)
    // REDUNDANT
    if ((validate_packet(MIT_CMD_ATTESTREQ) != SUCCESS_RETURN) ||
        (validate_packet(MIT_CMD_ATTESTREQ) != SUCCESS_RETURN) ||
        (validate_packet(MIT_CMD_ATTESTREQ) != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    ret = mit_decrypt(packet, comp_plaintext);
    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    delay_rnd;

    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    if (mit_ConstantCompare_nonce(session.incoming_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(receive_buffer, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    delay_rnd;

    increment_nonce(&session.incoming_nonce, &old_nonce);
    increment_nonce(&session.incoming_nonce, &old_nonce);
    increment_nonce(&session.incoming_nonce, &old_nonce);
    /***********************/

    // Step 1: Generate random challenge r2
    // REDUNDANT
    get_random_challenge(&r2);
    get_random_challenge(&r2);
    get_random_challenge(&r2);

    delay_rnd;

    // Step 2: Store r2 in response packet
    // REDUNDANT
    memcpy(attestReq->r2.rawBytes, r2.rawBytes, sizeof(mit_challenge_t));
    memcpy(attestReq->r2.rawBytes, r2.rawBytes, sizeof(mit_challenge_t));
    memcpy(attestReq->r2.rawBytes, r2.rawBytes, sizeof(mit_challenge_t));

    delay_rnd;

    // Step 3: Send response packet
    ret = make_mit_packet(COMPONENT_ID, MIT_CMD_ATTESTREQ, attestReq->rawBytes, sizeof(mit_message_attestreq_t));
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ret;
    }

    send_packet_and_ack((mit_packet_t *)transmit_buffer);

    // Step 4: Wait to receive a packet
    len = wait_and_receive_packet(receive_buffer);
    if (len <= sizeof(mit_comp_id_t)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Step 5: Validate packet
    // REDUNDANT
    if ((validate_packet(MIT_CMD_ATTEST) != SUCCESS_RETURN) ||
        (validate_packet(MIT_CMD_ATTEST) != SUCCESS_RETURN) ||
        (validate_packet(MIT_CMD_ATTEST) != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    ret = mit_decrypt(packet, comp_plaintext);
    // REDUNDANT
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        return ERROR_RETURN;
    }

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    delay_rnd;

    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    if (mit_ConstantCompare_nonce(session.incoming_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(receive_buffer, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    delay_rnd;

    increment_nonce(&session.incoming_nonce, &old_nonce);
    increment_nonce(&session.incoming_nonce, &old_nonce);
    increment_nonce(&session.incoming_nonce, &old_nonce);
    /***********************/

    // Step 6: Validate r2 in attest response
    // REDUNDANT
    if ((mit_ConstantCompare_challenge(attest->r2.rawBytes, r2.rawBytes) != 0) ||
        (mit_ConstantCompare_challenge(attest->r2.rawBytes, r2.rawBytes) != 0) ||
        (mit_ConstantCompare_challenge(attest->r2.rawBytes, r2.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Step 7: Stuff with attestation data
    memset(attest->rawBytes, 0, sizeof(mit_message_attest_t));
    len = sprintf(attest->customerData, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;

    ret = make_mit_packet(COMPONENT_ID, MIT_CMD_ATTEST, attest->rawBytes, sizeof(mit_message_attest_t));
    if (ret != SUCCESS_RETURN) {
        return ret;
    }

    send_packet_and_ack((mit_packet_t *)transmit_buffer);

    return SUCCESS_RETURN;
}

int __attribute__((optimize("O0"))) process_init_session() {
    delay_rnd;

    // Just double-check :)
    if (valid_session()) {
        return ERROR_RETURN;
    }

    int ret = ERROR_RETURN;
    mit_packet_t * packet = (mit_packet_t *) receive_buffer;
    mit_nonce_t old_nonce = {0};


    /*************** VALIDATE RECEIVED PACKET ****************/

    delay_rnd;

    if ((packet->ad.comp_id != COMPONENT_ID) ||
        (packet->ad.comp_id != COMPONENT_ID) ||
        (packet->ad.comp_id != COMPONENT_ID)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    if ((packet->ad.for_ap != false) ||
        (packet->ad.for_ap != false) ||
        (packet->ad.for_ap != false)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    if ((packet->ad.len != sizeof(mit_message_init_t)) ||
        (packet->ad.len != sizeof(mit_message_init_t)) ||
        (packet->ad.len != sizeof(mit_message_init_t))) {
        return ERROR_RETURN;
    }

    delay_rnd;

    if ((packet->ad.opcode != MIT_CMD_INIT) ||
        (packet->ad.opcode != MIT_CMD_INIT) ||
        (packet->ad.opcode != MIT_CMD_INIT)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Validate authTag field
    ret = mit_decrypt(packet, comp_plaintext);
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        memset(comp_plaintext, 0, COMP_PLAINTEXT_LEN);
        return ERROR_RETURN;
    }

    delay_rnd;

    // If packet's nonce, and the message's ap_nonce don't match, ignore.
    mit_message_init_t * received = (mit_message_init_t *)comp_plaintext;
    if ((mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, received->ap_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, received->ap_nonce.rawBytes) != 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, received->ap_nonce.rawBytes) != 0)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Save incoming nonce
    memcpy(session.incoming_nonce.rawBytes, received->ap_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(session.incoming_nonce.rawBytes, received->ap_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(session.incoming_nonce.rawBytes, received->ap_nonce.rawBytes, sizeof(mit_nonce_t));

    /***** Send init response back *****/
    // Copy our nonce into response message
    mit_message_init_t * outgoing = (mit_message_init_t *)comp_plaintext;
    
    delay_rnd;

    memcpy(outgoing->component_nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(outgoing->component_nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(outgoing->component_nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    packet = (mit_packet_t *)transmit_buffer;
    set_ad(packet, COMPONENT_ID, MIT_CMD_INIT, sizeof(mit_message_init_t));
    memcpy(packet->ad.nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    ret = mit_encrypt(packet, comp_plaintext, sizeof(mit_message_init_t));
    if ((ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN) ||
        (ret != SUCCESS_RETURN)) {
        memset(packet, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    delay_rnd;

    memcpy(old_nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    if (mit_ConstantCompare_nonce(session.outgoing_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(transmit_buffer, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    delay_rnd;

    increment_nonce(&session.outgoing_nonce, &old_nonce);
    increment_nonce(&session.outgoing_nonce, &old_nonce);
    increment_nonce(&session.outgoing_nonce, &old_nonce);
    /***********************/

    /*** INCREMENT NONCE ***/
    memset(old_nonce.rawBytes, 0, sizeof(mit_nonce_t));

    delay_rnd;

    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));
    memcpy(old_nonce.rawBytes, session.incoming_nonce.rawBytes, sizeof(mit_nonce_t));

    delay_rnd;

    if (mit_ConstantCompare_nonce(session.incoming_nonce.rawBytes, old_nonce.rawBytes) != 0) {
        memset(receive_buffer, 0, sizeof(mit_packet_t));
        return ERROR_RETURN;
    }

    delay_rnd;

    increment_nonce(&session.incoming_nonce, &old_nonce);
    increment_nonce(&session.incoming_nonce, &old_nonce);
    increment_nonce(&session.incoming_nonce, &old_nonce);
    /***********************/

    send_packet_and_ack(packet);
    return SUCCESS_RETURN;
}

/*********************************** MAIN *************************************/

int main(void) {
    // Enable Global Interrupts
    __enable_irq();

    // MIT: Initialize our custom features
    common_init();
    // REDUNDANT
    session_init();
    session_init();
    session_init();
    
    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);

    int len, ret;

    while (1) {
        // REDUNDANT
        memset(receive_buffer, 0, MAX_I2C_MESSAGE_LEN);
        memset(receive_buffer, 0, MAX_I2C_MESSAGE_LEN);
        memset(receive_buffer, 0, MAX_I2C_MESSAGE_LEN);

        // Wait for a packet
        len = wait_and_receive_packet(receive_buffer);

        delay_rnd;

        // Special handling for scan commands
        if (len == sizeof(mit_comp_id_t)) {
            send_scan_and_ack(COMPONENT_ID);
            continue;
        }

        // REDUNDANT
        if (valid_session() && valid_session() && valid_session()) {
            // Normal command processing
            ret = component_process_cmd();
        } else {
            // Special handling while waiting for init
            ret = process_init_session();
        }

        // Send one-byte ack if command is invalid.
        if (ret != SUCCESS_RETURN) {
            send_ack();
        }
    }
}
