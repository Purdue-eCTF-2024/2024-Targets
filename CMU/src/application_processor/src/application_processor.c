/**
 * @file application_processor.c
 * @author Plaid Parliament of Pwning
 * @brief This file implements the MISC application processor
 * 
 * Contains functions that implement the functional and security requirements of the MISC application processor.
 * 
 * @copyright Copyright (c) 2024, Carnegie Mellon University
 */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "flc.h"
#include "icc.h"

#include "ticks.h"
#include "led.h"
#include "host_messaging.h"
#include "mxc_sys.h"
#include "mxc_delay.h"
#include "mpu_armv7.h"

#include "hardware_init.h"
#include "crypto_wrappers.h"
#include "boot_blob.h"
#include "keys.h"
#include "rng.h"
#include "encrypted.h"
#include "util.h"

#include "comm_types.h"
#include "comm_link.h"
#include "sec_link.h"

#include "fiproc.h"

#include "secure_snd_rcv.h"

#include "defense_lockout.h"

/********************************* CONSTANTS **********************************/

// Library call return types
#define CMD_BUF_LEN 32
#define RAND_BUF_LEN 24
#define REPLACEMENT_TOKEN_BUF_LEN 16
#define ATTESTATION_PIN_LEN 6


/**
 * @brief Secure send/receive root key
 */
uint8_t secure_send_root_key[CC_ENC_SYM_KEY_LEN];

/******************************* POST BOOT FUNCTIONALITY *********************************/

#define MAX_COMPONENTS 256
/**
 * @brief Secure send/receive sequence numbers for each component
 */
uint32_t COMP_SEQ_NUMS[MAX_COMPONENTS] = {0};

/**
 * @brief Send a packet to specified component
 * 
 * Intended to be used INTERNALLY within this file
 * Validates sender/recv id, seq num
 * 
 * @param secure_msg message to be sent to component
 * @param address address of component
 * @return SUCCESS_RETURN if everything succeeds, ERROR_RETURN on error
*/
int internal_secure_send(uint8_t address, secure_msg_t* secure_msg) {

    // Prepare the secure send message
    secure_msg->sender_id = AP_ID; 
    secure_msg->receiver_id = address;
    secure_msg->seq_num = COMP_SEQ_NUMS[address];

    // A buffer to hold the encrypted message
    uint8_t encrypted_msg[sizeof(secure_msg_t) + CC_ENC_SYM_METADATA_LEN];

    /* Encrypt the message with the secure send subkey, then wipe secrets */

    // Generate 24 bytes of nonce for AEAD encryption
    uint8_t rng_bytes[24];
    rng_generate_bulk_fast(rng_bytes, sizeof(rng_bytes));

    // Derive the secure send subkey from the secure send root key
    uint8_t k_sss_id[CC_ENC_SYM_KEY_LEN] = {0x0};
    FIPROC_DELAY_WRAP();
    cc_kdf_sec_send_sub_key(k_sss_id, secure_send_root_key, (uint32_t) address);

    FIPROC_DELAY_WRAP();
    // Encrypt the message with secure send sub key
    cc_encrypt_symmetric(encrypted_msg, (uint8_t*)secure_msg, sizeof(secure_msg_t), k_sss_id, rng_bytes);

    // Wipe the random bytes and secure send sub key
    crypto_wipe(rng_bytes, sizeof(rng_bytes));
    crypto_wipe(k_sss_id, sizeof(k_sss_id));

    /* =============================================== */

    FIPROC_DELAY_WRAP();
    // Send Packet
    if (sec_link_send_and_wait_ack(encrypted_msg, sizeof(encrypted_msg), address, 20) != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }

    FIPROC_DELAY_WRAP();

    // Increment SEQ num of the target component
    COMP_SEQ_NUMS[address]++;

    FIPROC_DELAY_WRAP();

    // If we reached this point, everything worked as expected
    return SUCCESS_RETURN;
}

/**
 * @brief Receive a packet from specified component
 * 
 * Intended to be used INTERNALLY within this file
 * Validates sender/recv id, seq num
 * 
 * @param secure_msg message received, decrypted and passed by reference to caller
 * @param address address of component
 * @return SUCCESS_RETURN if everything succeeds, ERROR_RETURN on error
*/
int internal_secure_receive(uint8_t address, secure_msg_t* secure_msg) {

    // A buffer to receive the encrypted message
    uint8_t recv_buffer[sizeof(secure_msg_t) + CC_ENC_SYM_METADATA_LEN];
    int received_len = sec_link_receive(recv_buffer, sizeof(recv_buffer), address);

    FIPROC_DELAY_WRAP();

    // Check if the size of the message we received was expected
    if (received_len != sizeof(recv_buffer)) {
        // Unexpected size received
        return ERROR_RETURN;
    }

    // Prepare secure send subkey for the target component
    uint8_t k_sss_id[CC_ENC_SYM_KEY_LEN] = {0x0};
    FIPROC_DELAY_WRAP();
    cc_kdf_sec_send_sub_key(k_sss_id, secure_send_root_key, address);

    // Attempt to decrypt the received message
    FIPROC_DELAY_WRAP();
    int result = cc_decrypt_symmetric((uint8_t*)secure_msg, recv_buffer, sizeof(secure_msg_t), k_sss_id);

    // Don't need the key at this point, wipe it immediately
    crypto_wipe(k_sss_id, sizeof(k_sss_id));

    FIPROC_DELAY_WRAP();
    // Result will be 0 if success, checking if it was success
    if (result != SUCCESS_RETURN) {
        // Decryption has failed
        return ERROR_RETURN;
    }

    FIPROC_DELAY_WRAP();
    // Validate the sequence number
    if (secure_msg->seq_num != COMP_SEQ_NUMS[address]) {
        // Someone has tampered with the encryption or attempted a replay
        return ERROR_RETURN;
    }
    
    FIPROC_DELAY_WRAP();
    // Check if this message is from the expected component
    if (secure_msg->sender_id != address) {
        // Someone has tampered with the encryption or attempted a replay
        return ERROR_RETURN;
    }
    
    FIPROC_DELAY_WRAP();
    // Check if this message was intended for the AP
    if (secure_msg->receiver_id != AP_ID) {
        // Someone has tampered with the encryption or attempted a replay
        return ERROR_RETURN;
    } 

    // Increment the seq num for the target component
    COMP_SEQ_NUMS[address]++;

    FIPROC_DELAY_WRAP();

    // Everything worked as expected if we reached this point
    return SUCCESS_RETURN;
}

/**
 * @brief Secure Send 
 * 
 * Securely send data over link layer. This function is utilized in POST_BOOT functionality.
 * 
 * @param address address of recipient
 * @param buffer pointer to data to be send
 * @param len size of data to be sent 
*/
int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    fiproc_load_pool();
    rng_pool_update();

    if (len > MAX_MSG_LEN) {
        // HCF: The caller has violated the function's contract,
        // this can only be caused by a hardware fault.
        HALT_AND_CATCH_FIRE();
    }

    /* Step 1: AP sends a REQ-TO-SEND message to the Component */
    
    // Prepare the REQ-TO-SEND message
    secure_msg_t req_to_send_msg = { 0 };
    req_to_send_msg.message_type = COMM_AP_REQ_SECURE_SEND;

    FIPROC_DELAY_WRAP();

    // Loop to retry sending the message in case component misses the first message
    while (FAILED(internal_secure_send(address, &req_to_send_msg))) {
        MXC_Delay(RETRY_DELAY_TX);
        FIPROC_DELAY_WRAP();
    }

    /* Step 2: Comp sends a nonce as a challenge to the AP */

    // Receive Nonce packet
    secure_msg_t recv_nonce_msg = { 0 };

    uint32_t comp_nonce = 0;
    while (1) {
        // Attempt sending the nonce message to the component
        if (FAILED(internal_secure_receive(address, &recv_nonce_msg))) {
            MXC_Delay(RETRY_DELAY_RX);
            continue;
        }

        FIPROC_DELAY_WRAP();

        // Verify the type of the message, check if its actually a nonce packet
        if (recv_nonce_msg.message_type != COMM_COMP_RESP_SECURE_NONCE) {
            // If we received the wrong message type, go back to listening
            MXC_Delay(RETRY_DELAY_RX);
            continue;
        }

        FIPROC_DELAY_WRAP();

        if (recv_nonce_msg.message_len != 0) {
            MXC_Delay(RETRY_DELAY_RX);
            continue;
        }

        FIPROC_DELAY_WRAP();

        // Take note of the nonce
        comp_nonce = recv_nonce_msg.nonce;
        break;
    }

    /* Step 3: Send the actual message (that the Post-Boot code wants us to send) to the component */

    // Prepare the actual message to be sent to the Component
    secure_msg_t secure_data_msg = { 0 };
    secure_data_msg.message_type = COMM_AP_REQ_SECURE_MSG;
    FIPROC_DELAY_WRAP();
    SECURE_MEMCPY(secure_data_msg.message, buffer, len);


    // Fill up the rest of the message struct
    secure_data_msg.message_len = len;
    // Use the same nonce that the Component sent earlier
    secure_data_msg.nonce = comp_nonce;

    volatile int fi_valid = 0;

    FIPROC_DELAY_WRAP();
    while (1) {
        // Try sending the message to the component
        while (FAILED(internal_secure_send(address, &secure_data_msg))) {
            MXC_Delay(RETRY_DELAY_TX);
        }

        FIPROC_DELAY_WRAP();

        // Try receiving an ACK to confirm the process completed
        secure_msg_t secure_msg_ack = { 0 };
        if (internal_secure_receive(address, &secure_msg_ack) != SUCCESS_RETURN) {
            // Message not delivered/ack, try resending
            MXC_Delay(RETRY_DELAY_RX);
            continue;
        }

        FIPROC_DELAY_WRAP();
        if (secure_msg_ack.message_type != COMM_COMP_RESP_SECURE_ACK) {
            // Incorrect message received, try resending
            MXC_Delay(RETRY_DELAY_RX);
            continue;
        }

        // ASSERT: redundant check with above
        SEC_ASSERT(((volatile secure_msg_t) secure_msg_ack).message_type == COMM_COMP_RESP_SECURE_ACK);

        fi_valid = (((volatile secure_msg_t) secure_msg_ack).message_type == COMM_COMP_RESP_SECURE_ACK); 
        
        break;
    }

    SEC_ASSERT(fi_valid == 1);
    fiproc_ranged_delay();
    SEC_ASSERT(fi_valid == 1);


    // Everything worked as expected, return Success
    return SUCCESS_RETURN;
}

/**
 * @brief Secure Receive
 * 
 * Securely receive data over link layer. This function is utilized in POST_BOOT functionality.
 * 
 * @param address address of sender
 * @param buffer pointer to buffer to receive data to
 * @return number of bytes received on success, negative on error
*/
int secure_receive(uint8_t address, uint8_t* buffer) {
    fiproc_load_pool();
    rng_pool_update();

    /* Step 1: Send Request-to-Receive message to the component */

    // Struct to receive actual message from component
    secure_msg_t secure_msg_data = { 0 };

    // Prepare the Req to Receive Packet
    secure_msg_t secure_msg_req_recv = { 0 };

    secure_msg_req_recv.message_type = COMM_AP_REQ_SECURE_RECEIVE;

    // Generate a nonce
    uint32_t nonce;
    rng_generate_bulk_fast((uint8_t*)&nonce, sizeof(nonce));
    secure_msg_req_recv.nonce = nonce;

    FIPROC_DELAY_WRAP();

    volatile int fi_valid = 0;

    while (1) {
        // Send the Req-to-Receive message to the component
        while (FAILED(internal_secure_send(address, &secure_msg_req_recv))) {
            MXC_Delay(RETRY_DELAY_TX);
        }

        /* Step 2: Try to receive the message from the component */

        // Clear the stack space of secure_msg_data before using it
        crypto_wipe(&secure_msg_data, sizeof(secure_msg_data));
        // Try receiving the message from the component
        while (FAILED(internal_secure_receive(address, &secure_msg_data))) {
            MXC_Delay(RETRY_DELAY_RX);
        }

        // Validate the size of the message
        if (secure_msg_data.message_len > MAX_MSG_LEN) {
            // The message len is more than expected. Unacceptable.
            MXC_Delay(RETRY_DELAY_RX);
            continue;
        } 

        SEC_ASSERT(((volatile secure_msg_t) secure_msg_data).message_len <= MAX_MSG_LEN);

        // Validate Messsage
        if (secure_msg_data.message_type != COMM_COMP_RESP_SECURE_MSG) {
            MXC_Delay(RETRY_DELAY_RX);
            continue;
        }

        // Validate received nonce
        if (secure_msg_data.nonce != nonce) {
            MXC_Delay(RETRY_DELAY_RX);
            continue;
        } 

        SEC_ASSERT(((volatile secure_msg_t) secure_msg_data).message_type == COMM_COMP_RESP_SECURE_MSG);
        fi_valid = (((volatile secure_msg_t) secure_msg_data).message_type == COMM_COMP_RESP_SECURE_MSG); 

        SEC_ASSERT(((volatile secure_msg_t) secure_msg_data).nonce == nonce);
        fi_valid &= (((volatile secure_msg_t) secure_msg_data).nonce == nonce); 

        // Copy the received message to the buffer sent by the Post-boot code
        SECURE_MEMCPY(buffer, secure_msg_data.message, secure_msg_data.message_len);

        SEC_ASSERT(fi_valid == 1);
        fiproc_ranged_delay();
        SEC_ASSERT(fi_valid == 1);
        
        // Return the num of bytes received on success
        return secure_msg_data.message_len;
    }
}

/**
 * @brief Get Provisioned IDs
 * 
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT functionality.
 * 
 * @param buffer buffer to copy provisioned IDs into
 * @return number of ids
*/
int get_provisioned_ids(uint32_t* buffer) {
    SECURE_MEMCPY(buffer, BOOT_BLOB_FLASH->provisioned_ids, COMPONENT_CNT * sizeof(uint32_t));
    return COMPONENT_CNT;
}

/******************************* POST BOOT FUNCTIONALITY END *********************************/

/******************************** COMPONENT COMMS ********************************/

/**
 * @brief Check if the new and old components are provisioned and not reserved
 * 
 * @param component_id_in new component that goes in
 * @param component_id_out old component that goes out
 * @return int 0 on success, negative on error
 */
int replace_check_if_components_are_provisioned_and_legal(uint32_t component_id_in, uint32_t component_id_out){
    uint8_t in_addr = component_id_to_i2c_address(component_id_in);
    uint8_t out_addr = component_id_to_i2c_address(component_id_out);

    boot_blob_page_t *boot_page = BOOT_BLOB_FLASH; 

    // I2C Blacklist - these conflict with separate device on MAX78000FTHR
    if(!is_valid_i2c_address(in_addr) || !is_valid_i2c_address(out_addr)){
        return ERROR_RETURN;
    }

    // Prevents insertion of duplicates
    for (int i=0; i<COMPONENT_CNT; i++){
        if (component_id_in == boot_page->provisioned_ids[i]){
            return ERROR_RETURN;
        }
    }

    // Checks if component to replace is provisioned
    for (int i=0; i<COMPONENT_CNT; i++){
        if (component_id_out == boot_page->provisioned_ids[i]){
            return SUCCESS_RETURN;
        }
    }
    
    return ERROR_RETURN;
}

/**
 * @brief Checks if the component is already provisioned
 * 
 * @param component_id component id
 * @return 0 on success, negative on error
 */
int attest_check_if_component_provisioned(uint32_t component_id){
    uint8_t addr = component_id_to_i2c_address(component_id);

    boot_blob_page_t *boot_page = BOOT_BLOB_FLASH; 

    // I2C Blacklist - these conflict with separate device on MAX78000FTHR
    if(!is_valid_i2c_address(addr)){
        return ERROR_RETURN;
    }

    // Checks if component is provisioned
    for (int i=0; i<COMPONENT_CNT; i++){
        if (component_id == boot_page->provisioned_ids[i]){
            return SUCCESS_RETURN;
        }
    }
    
    return ERROR_RETURN;
}


/**
 * @brief Scans through all components and lists ids of components present
 */
void scan_components(void) {
    uint32_t component_cnt = COMPONENT_CNT;

    // Print out provisioned component IDs
    for (unsigned i = 0; i < component_cnt; i++) {
        print_info_start("P>");
        print_hex_integer(BOOT_BLOB_FLASH->provisioned_ids[i], true);
        print_info_end("\n");
    }

    // Buffers for board link communication
    uint8_t receive_buffer[COMM_MAX_MSG_LEN] = {0};
    uint8_t transmit_buffer[COMM_MAX_MSG_LEN] = {0};

    // Scan command to each component 
    for (uint8_t addr = 0x8; addr < 0x7F; addr++) {
        // I2C Blacklist - these conflict with separate device on MAX78000FTHR
        if(!is_valid_i2c_address(addr)){
            continue;
        }

        // Create command message
        comm_ap_req_list_ping_t *ping =
            (comm_ap_req_list_ping_t *)transmit_buffer;
        ping->msg_info.msg_type = COMM_AP_REQ_LIST_PING;

        // Poll the devices on the bus with 4ms timeout
        int result = sec_link_poll(addr, 4);
        if (result != SUCCESS_RETURN) {
            continue;
        }

        // If the device exists on the bus, send it a scan request to get its ID
        result = sec_link_send_and_wait_ack(transmit_buffer, COMM_MAX_MSG_LEN, addr, 20);
        crypto_wipe(transmit_buffer, COMM_MAX_MSG_LEN);
        if (result != SUCCESS_RETURN) {
            continue;
        }
    
        // Receive message
        int32_t len = sec_link_receive(receive_buffer, sizeof(comm_comp_resp_list_pong_t), addr);
        if (len < 0) {
            crypto_wipe(receive_buffer, COMM_MAX_MSG_LEN);
            continue;
        }

        comm_comp_resp_list_pong_t* pong = (comm_comp_resp_list_pong_t*) receive_buffer;
        if (pong->msg_info.msg_type == COMM_COMP_RESP_LIST_PONG) {
            print_info_start("F>");
            print_hex_integer(pong->comp_id, true);
            print_info_end("\n");
        }

        crypto_wipe(receive_buffer, COMM_MAX_MSG_LEN);
    }
    print_success("List\n");
}

/**
 * @brief Attests component given Attestation Pin and Component ID 
 * 
 *   1. Host sends Attestation Pin (PIN) and Component ID (Cid ) to the AP
 *   2. The AP sends an Attestation Data request to the Component. 
 *   3. Once the component receives the request, it replies with the Attestation Data encrypted with the Attestation Subkey ({ADid}K_atts_id ) back to the AP. 
 *   4. AP attempts to decrypt the Attestation Root Key ({Kattr}KDF(PIN) ) using the given Attestation Pin using AEAD.  
 *   5. The AP derives the Attestation Subkey as Katts_id = KDF(Kattr || ID). 
 *   6. The AP decrypts the attestation data from each component using AEAD.
 *   7. If the decryption of each component succeeds, the Application Processor will forward it to the Host.
 *
 *  @param att_pin Attestation Pin 
 *  @param component_id Component ID
 *  @return Success Status of Attestation
 */
int attest_component(const char att_pin[ATTESTATION_PIN_LEN], uint32_t component_id) {
    int8_t attestation_success = SUCCESS_RETURN;
    int8_t decryption_success = ERROR_RETURN;

    defense_lockout_start();

    // 1. Recieve Attestation PIN and Component ID from Host: Done in the Tool

    // 2. The AP sends an Attestation Data request to the Component. 
    // 3. Once the component receives the request, it replies with the Attestation Data encrypted with the Attestation Subkey ({ADid}K_atts_id ) back to the AP. 
    // 3.1 Implemented on Component Side

    //Check if component has been Provisioned for
    if(attest_check_if_component_provisioned(component_id) != SUCCESS_RETURN){
        defense_lockout_clear(false);
        return ERROR_RETURN;
    }

    uint8_t att_data_enc[COMM_MAX_MSG_LEN] = {0};
    uint8_t attest_message_buf[COMM_MAX_MSG_LEN] = {0};

    comm_ap_req_ad_t *attest_message = (comm_ap_req_ad_t*)attest_message_buf;
    attest_message->msg_info.msg_type = COMM_AP_REQ_AD;

    int result = sec_link_send_and_wait_ack(attest_message_buf, COMM_MAX_MSG_LEN, component_id_to_i2c_address(component_id), 100);

    crypto_wipe(attest_message_buf, COMM_MAX_MSG_LEN);

    if (result != SUCCESS_RETURN) {
        defense_lockout_clear(false);
        crypto_wipe(att_data_enc, sizeof att_data_enc);
        crypto_wipe(attest_message, sizeof(comm_ap_req_ad_t)); 
        return ERROR_RETURN;
    }

    // Receive message
    int att_data_enc_len = sec_link_receive(att_data_enc, COMM_MAX_MSG_LEN, component_id_to_i2c_address(component_id));
    if (att_data_enc_len < 0) {
        defense_lockout_clear(false);
        crypto_wipe(att_data_enc, sizeof att_data_enc);
        crypto_wipe(attest_message, sizeof(comm_ap_req_ad_t)); 
        return ERROR_RETURN;
    }    

    //4. AP attempts to decrypt the Attestation Root Key ({Kattr}KDF(PIN)) using the given Attestation Pin using AEAD. 
    //Find KDF of PIN
    uint8_t att_pin_kdf[CC_ENC_SYM_KEY_LEN] = {0};
    cc_kdf_pin(att_pin_kdf, att_pin);

    //Attempt to decrypt Key
    uint8_t att_root_key[CC_ENC_SYM_KEY_LEN] = {0};
    //ATT_ROOT_KEY_ENCRYPTED is encrypted in flash
    decryption_success = cc_decrypt_symmetric(att_root_key,ATT_ROOT_KEY_ENCRYPTED, CC_ENC_SYM_KEY_LEN, att_pin_kdf);
    
    crypto_wipe(att_pin_kdf, CC_ENC_SYM_KEY_LEN);

    //If the decryption fails, fill it with zeros
    if(decryption_success < 0){ 
        crypto_wipe(att_root_key, CC_ENC_SYM_KEY_LEN);
        crypto_wipe(att_data_enc, COMM_MAX_MSG_LEN);
        attestation_success = ERROR_RETURN;
    }

    // 5. The AP derives the Attestation Subkey as Katts_id = KDF(Kattr || ID). 
    uint8_t att_subkey[CC_ROOTKEY_LENGTH] = {0};
    cc_kdf_att_sub_key(att_subkey, att_root_key, component_id);

    crypto_wipe(att_root_key, CC_ENC_SYM_KEY_LEN);

    // 6. The AP decrypts the attestation data from each component using AEAD.
    uint8_t att_data[COMM_MAX_MSG_LEN] = {0}; 
    decryption_success = cc_decrypt_symmetric(att_data, att_data_enc, sizeof(att_data_t), att_subkey);

    crypto_wipe(att_subkey, CC_ROOTKEY_LENGTH);
    crypto_wipe(att_data_enc, COMM_MAX_MSG_LEN);

    if(decryption_success < 0){
        attestation_success = ERROR_RETURN;
    }

    // 7. If the decryption of each component succeeds, the Application Processor will forward it to the Host.
    if(attestation_success == SUCCESS_RETURN){
        print_attestation_data(component_id, (void*)att_data);
        defense_lockout_clear(false);
    } else {
        // LOCKOUT: Incorrect PIN / failed decrypt = under attack
        defense_lockout_clear(true);
    }

    //Purge Buffers using crypto wipe
    crypto_wipe(att_data, COMM_MAX_MSG_LEN);
    
    return attestation_success;
}

/******************************** COMPONENT COMMS END ********************************/

/********************************* AP LOGIC ***********************************/

/**
 * @brief Check if there are duplicate provisioned component ids
 * 
 * @return 0 on success, negative on error
 */
int duplicate_provisioned_id_check(void) {
    boot_blob_page_t *boot_page = BOOT_BLOB_FLASH;
    for (int i=0; i < COMPONENT_CNT; i++){
        uint32_t id = boot_page->provisioned_ids[i];
        for (int j=i+1; j<COMPONENT_CNT;j++){
            if (id == boot_page->provisioned_ids[j]){
                return ERROR_RETURN;
            }
        }
    }    
    return SUCCESS_RETURN;
}

/**
 * @brief Gets AP boot Keys from each provisioned Component
 * 
 * ASSUMPTION - provisioned_ids are sorted in increasing order of component id
 * 
 * @param ap_boot_sub_keys output buffers for ap boot sub keys
 * @return return 0 on success, negative on error
 */
int get_ap_boot_sub_keys(uint8_t ap_boot_sub_keys[COMPONENT_CNT][CC_ENC_SYM_KEY_LEN]) {
    uint8_t receive_buffer[COMM_MAX_MSG_LEN] = {0};
    uint8_t transmit_buffer[COMM_MAX_MSG_LEN] = {0};

    boot_blob_page_t *boot_page = BOOT_BLOB_FLASH;


    for (size_t i=0; i< COMPONENT_CNT;i++) {
        comm_ap_req_boot_key_t* send_packet = (comm_ap_req_boot_key_t*) transmit_buffer;
        send_packet->msg_info.msg_type = COMM_AP_REQ_BOOT_KEY;

        comm_comp_resp_boot_key_t* recv_packet = (comm_comp_resp_boot_key_t*) receive_buffer;

        if (sec_link_send_and_wait_ack(transmit_buffer, COMM_MAX_MSG_LEN, component_id_to_i2c_address(boot_page->provisioned_ids[i]), 100) != SUCCESS_RETURN) {
            crypto_wipe(transmit_buffer, COMM_MAX_MSG_LEN);
            return ERROR_RETURN;
        }
        crypto_wipe(transmit_buffer, COMM_MAX_MSG_LEN);

        int resp_len = sec_link_receive(receive_buffer, sizeof(comm_comp_resp_boot_key_t), component_id_to_i2c_address(boot_page->provisioned_ids[i]));

        if (resp_len < 0){
            crypto_wipe(receive_buffer, COMM_MAX_MSG_LEN);
            return ERROR_RETURN;
        }

        if (resp_len != sizeof(comm_comp_resp_boot_key_t)){
            crypto_wipe(receive_buffer, COMM_MAX_MSG_LEN);
            return ERROR_RETURN;
        }

        if (recv_packet->msg_info.msg_type != COMM_COMP_RESP_BOOT_KEY){
            crypto_wipe(receive_buffer, COMM_MAX_MSG_LEN);
            return ERROR_RETURN;
        }


        SECURE_MEMCPY(ap_boot_sub_keys[i], recv_packet->ap_boot_sub_key, CC_ENC_SYM_KEY_LEN);
        crypto_wipe(receive_buffer, COMM_MAX_MSG_LEN); // Sanctioned by Andrew
    }

    return SUCCESS_RETURN;
}

/**
 * @brief Decrypts Boot Blob using ap_boot_sub_keys
 * 
 * @param blob output buffer for decrypted boot blob
 * @param ap_boot_sub_keys ap boot sub keys
 * @return 0 on success, negative on error
 */
int decrypt_boot_blob(boot_blob* blob, uint8_t ap_boot_sub_keys[COMPONENT_CNT][CC_ENC_SYM_KEY_LEN]) {
    uint8_t blob_to_decrypt[ENCRYPTED_BOOT_BLOB_LEN] = {0};
    uint8_t blob_after_decrypt[ENCRYPTED_BOOT_BLOB_LEN] = {0};
    boot_blob_page_t *boot_page = BOOT_BLOB_FLASH; 

    SECURE_MEMCPY(blob_to_decrypt, boot_page->encrypted_boot_blob, ENCRYPTED_BOOT_BLOB_LEN);

    for (size_t i = 0; i < COMPONENT_CNT; i++) {
        size_t size_after_decrypting = ENCRYPTED_BOOT_BLOB_LEN - ((i + 1) * CC_ENC_SYM_METADATA_LEN);
        size_t component_id_reverse = COMPONENT_CNT - 1 - i;

        if (cc_decrypt_symmetric(blob_after_decrypt, blob_to_decrypt, size_after_decrypting, ap_boot_sub_keys[component_id_reverse]) != SUCCESS_RETURN) {
            crypto_wipe(blob_to_decrypt, ENCRYPTED_BOOT_BLOB_LEN);
            crypto_wipe(blob_after_decrypt, ENCRYPTED_BOOT_BLOB_LEN);
            return ERROR_RETURN;
        }

        crypto_wipe(blob_to_decrypt, ENCRYPTED_BOOT_BLOB_LEN);

        SECURE_MEMCPY(blob_to_decrypt, blob_after_decrypt, size_after_decrypting);

        crypto_wipe(blob_after_decrypt, ENCRYPTED_BOOT_BLOB_LEN);
    }

    SECURE_MEMCPY((void*)blob, blob_to_decrypt, sizeof(boot_blob));

    return SUCCESS_RETURN;
}

/**
 * @brief Compute comp_boot_sub_keys using comp_boot_root_key using a key derivation function
 * 
 * @param comp_boot_sub_keys output buffer array for componenet boot sub keys
 * @param comp_boot_root_key component boot root key
 */
void compute_comp_boot_sub_keys(uint8_t comp_boot_sub_keys[COMPONENT_CNT][CC_ENC_SYM_KEY_LEN], uint8_t comp_boot_root_key[CC_ENC_SYM_KEY_LEN]){
    boot_blob_page_t *boot_page = BOOT_BLOB_FLASH; 

    for (int i = 0; i < COMPONENT_CNT; i++) {
        cc_kdf_comp_boot_sub_key(comp_boot_sub_keys[i], comp_boot_root_key, boot_page->provisioned_ids[i]);
    }
}

/**
 * @brief Boot Components by sending boot subkeys and acquire their boot msgs
 * 
 * ASSUMPTION - provisioned_ids are sorted in increasing order of component id
 * 
 * @param comp_boot_sub_keys component boot sub keys
 * @return int 0 on success, negative on error
 */
int boot_components(uint8_t comp_boot_sub_keys[COMPONENT_CNT][CC_ENC_SYM_KEY_LEN]){
    uint8_t receive_buffer[COMM_MAX_MSG_LEN] = {0};
    uint8_t transmit_buffer[COMM_MAX_MSG_LEN] = {0};

    boot_blob_page_t *boot_page = BOOT_BLOB_FLASH; 

    for (size_t i=0; i< COMPONENT_CNT;i++) {
        comm_ap_req_comp_boot_t* send_packet = (comm_ap_req_comp_boot_t*) transmit_buffer;
        send_packet->msg_info.msg_type = COMM_AP_REQ_COMP_BOOT;
        SECURE_MEMCPY(send_packet->comp_boot_sub_key, comp_boot_sub_keys[i], CC_ENC_SYM_KEY_LEN);

        comm_comp_resp_boot_msg_t* recv_packet = (comm_comp_resp_boot_msg_t*) receive_buffer;

        if (sec_link_send_and_wait_ack(transmit_buffer, COMM_MAX_MSG_LEN, component_id_to_i2c_address(boot_page->provisioned_ids[i]), 100) != SUCCESS_RETURN) {
            crypto_wipe(transmit_buffer, COMM_MAX_MSG_LEN);
            return ERROR_RETURN;
        }
        crypto_wipe(transmit_buffer, COMM_MAX_MSG_LEN);

        int resp_len = sec_link_receive(receive_buffer, sizeof(comm_comp_resp_boot_msg_t), component_id_to_i2c_address(boot_page->provisioned_ids[i]));

        if (resp_len < 0){
            crypto_wipe(receive_buffer, COMM_MAX_MSG_LEN);
            return ERROR_RETURN;
        }

        if (resp_len != sizeof(comm_comp_resp_boot_msg_t)){
            crypto_wipe(receive_buffer, COMM_MAX_MSG_LEN);
            return ERROR_RETURN;
        }
        if (recv_packet->msg_info.msg_type != COMM_COMP_RESP_BOOT_MSG){
            crypto_wipe(receive_buffer, COMM_MAX_MSG_LEN);
            return ERROR_RETURN;
        }

        print_component_boot(boot_page->provisioned_ids[i], (void *) recv_packet->boot_msg);
        crypto_wipe(receive_buffer, COMM_MAX_MSG_LEN);
    }

    return SUCCESS_RETURN;
}


/**
 * @brief Linker variables that denote where the encrypted application code is kept
 */
extern uint8_t _code_encrypted, _code_decrypted, _ecode_decrypted;

/**
 * @brief Decrypts code after boot
 *
 * Decrypt the application code that was encrypted before load time.
 * @param ap_code_key application boot key
 * @return int 0 on success, negative on error
 */
int decrypt_post_boot_code(uint8_t ap_code_key[CC_ENC_SYM_KEY_LEN]){
    size_t text_sz = (&_ecode_decrypted) - (&_code_decrypted);
    if (cc_decrypt_symmetric(&_code_decrypted, &_code_encrypted, text_sz,  ap_code_key) != SUCCESS_RETURN){
        return ERROR_RETURN;
    }

    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(3, 0x20000000), // to 0x2000_4000 (16KiB)
        // Execute, read-only
        ARM_MPU_RASR(0, ARM_MPU_AP_PRO, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_16KB)
    );

    return SUCCESS_RETURN;
}

/**
 * @brief Boot the components and board if the components validate
 * 
 * 1) Check duplicate provisioned ids - proceed if none
 * 2) Get ap boot sub keys from components
 * 3) Decrypt the boot blob
 * 4) Compute component boot sub keys
 * 5) Send them to the components
 * 6) Receive the component boot messages and print them
 * 7) Print the AP boot message
 * 8) Decrypt the post boot code
 * 9) Boot!!
 */
void attempt_boot(void) {
    uint8_t ap_boot_sub_keys[COMPONENT_CNT][CC_ENC_SYM_KEY_LEN] = {0};
    boot_blob decrypted_boot_blob; 
    uint8_t comp_boot_sub_keys[COMPONENT_CNT][CC_ENC_SYM_KEY_LEN] = {0};

    if (duplicate_provisioned_id_check() != SUCCESS_RETURN) {
        print_error("Boot failed\n");
        return;
    }

    if (get_ap_boot_sub_keys(ap_boot_sub_keys) != SUCCESS_RETURN) {
        print_error("Boot failed\n");
        for (int i = 0; i < COMPONENT_CNT; i++) {
            crypto_wipe(ap_boot_sub_keys[i], CC_ENC_SYM_KEY_LEN);
        }
        return;
    }

    if (decrypt_boot_blob(&decrypted_boot_blob, ap_boot_sub_keys) != SUCCESS_RETURN) {
        print_error("Boot failed\n");
        for (int i = 0; i < COMPONENT_CNT; i++) {
            crypto_wipe(ap_boot_sub_keys[i], CC_ENC_SYM_KEY_LEN);
        }

        return;
    }

    for (int i = 0; i < COMPONENT_CNT; i++) {
        crypto_wipe(ap_boot_sub_keys[i], CC_ENC_SYM_KEY_LEN);
    }

    compute_comp_boot_sub_keys(comp_boot_sub_keys, decrypted_boot_blob.comp_boot_root_key);

    if (boot_components(comp_boot_sub_keys) != SUCCESS_RETURN) {
        print_error("Boot failed\n");
        for (int i = 0; i < COMPONENT_CNT; i++) {
            crypto_wipe(comp_boot_sub_keys[i], CC_ENC_SYM_KEY_LEN);
        }
        return;
    }

    crypto_wipe(decrypted_boot_blob.comp_boot_root_key, CC_ENC_SYM_KEY_LEN); 

    for (int i = 0; i < COMPONENT_CNT; i++) {
        crypto_wipe(comp_boot_sub_keys[i], CC_ENC_SYM_KEY_LEN);
    }

    print_ap_boot((void *) decrypted_boot_blob.boot_msg);

    if (decrypt_post_boot_code(decrypted_boot_blob.ap_code_key) != SUCCESS_RETURN) {
        print_error("Boot failed\n");
        crypto_wipe(&decrypted_boot_blob, sizeof(decrypted_boot_blob));
        return;
    }

    SECURE_MEMCPY(secure_send_root_key, decrypted_boot_blob.secure_send_root_key, CC_ENC_SYM_KEY_LEN);

    crypto_wipe(&decrypted_boot_blob, sizeof(decrypted_boot_blob));
    
    defense_lockout_clear(false);

    // Boot
    rng_pool_update();
    boot();
}

/**
 * @brief Compute ap_boot_sub_keys using ap_boot_root_key
 * 
 * @param ap_boot_sub_keys output buffer array for ap boot sub keys
 * @param ap_boot_root_key ap boot root key
 * @param provisioned_ids array of provisioned ids
 */
void compute_ap_boot_sub_keys(uint8_t ap_boot_sub_keys[COMPONENT_CNT][CC_ENC_SYM_KEY_LEN], uint8_t ap_boot_root_key[CC_ENC_SYM_KEY_LEN], uint32_t provisioned_ids[COMPONENT_CNT]){
    for (int i = 0; i < COMPONENT_CNT; i++) {
        cc_kdf_ap_boot_sub_key(ap_boot_sub_keys[i], ap_boot_root_key, provisioned_ids[i]);
    }
}

/**
 * @brief Replace and sort provisioned ids
 * 
 * @param component_id_in new component id that goes in
 * @param component_id_out old component id that goes out
 * @param provisioned_ids array of provisioned ids
 */
void replace_and_sort_provisioned_ids(uint32_t component_id_in, uint32_t component_id_out, uint32_t provisioned_ids[COMPONENT_CNT]){ 
    // Replace in with out
    for (int i = 0; i < COMPONENT_CNT; i++){
        if (component_id_out == provisioned_ids[i]){
            provisioned_ids[i] = component_id_in;
        }
    }

    //Sort provisioned ids using simple bubble sort
    bool swapped = true; 

    while (swapped){
        swapped = false;
        for (int i = 1; i <= COMPONENT_CNT -1; i++){
            if (provisioned_ids[i-1] > provisioned_ids[i]){
                uint32_t temp = provisioned_ids[i];
                provisioned_ids[i] = provisioned_ids[i-1];
                provisioned_ids[i-1] = temp;
                swapped = true;
            }

        }
    }
}


/**
 * @brief Encrypts Boot Blob using ap_boot_sub_keys
 * 
 * @param encrypted_boot_blob output buffer for encrypted boot blob
 * @param decrypted_blob decrypted boot blob
 * @param ap_boot_sub_keys ap boot sub keys
 */
void encrypt_boot_blob(uint8_t encrypted_boot_blob[ENCRYPTED_BOOT_BLOB_LEN], boot_blob* decrypted_blob, uint8_t ap_boot_sub_keys[COMPONENT_CNT][CC_ENC_SYM_KEY_LEN]) {
    uint8_t blob_to_encrypt[ENCRYPTED_BOOT_BLOB_LEN] = {0};
    uint8_t blob_after_encrypt[ENCRYPTED_BOOT_BLOB_LEN] = {0};
    uint8_t rand_buf[RAND_BUF_LEN] = {0}; 

    SECURE_MEMCPY(blob_to_encrypt, (void *) decrypted_blob, sizeof(boot_blob));

    for (size_t i = 0; i < COMPONENT_CNT; i++) {
        size_t size_before_encrypting = sizeof(boot_blob) + (i * CC_ENC_SYM_METADATA_LEN);
        size_t size_after_encrypting = sizeof(boot_blob) + ((i + 1) * CC_ENC_SYM_METADATA_LEN);
     
        rng_generate_bulk((void *) rand_buf, RAND_BUF_LEN);

        cc_encrypt_symmetric(blob_after_encrypt, blob_to_encrypt, size_before_encrypting, ap_boot_sub_keys[i], rand_buf);

        crypto_wipe(blob_to_encrypt, ENCRYPTED_BOOT_BLOB_LEN);
        crypto_wipe(rand_buf, RAND_BUF_LEN);

        SECURE_MEMCPY(blob_to_encrypt, blob_after_encrypt, size_after_encrypting);
        
        crypto_wipe(blob_after_encrypt, ENCRYPTED_BOOT_BLOB_LEN);
    }

    SECURE_MEMCPY(encrypted_boot_blob, blob_to_encrypt, ENCRYPTED_BOOT_BLOB_LEN);
    crypto_wipe(blob_to_encrypt, ENCRYPTED_BOOT_BLOB_LEN);
}

/**
 * @brief Replace a component if the PIN is correct
 * 
 * 1) Check if there are duplicate provisioned ids
 * 2) Check if the component ids are provioned and not reserved
 * 3) Derive the replaceement key from the replacement token
 * 4) Decrypt and get the ap boot root key
 * 5) Derive the ap boot sub keys using the key derivation function on the ap boot root key
 * 6) Decrypt boot blob
 * 7) Replace the old component id with the new one (in sorted order)
 * 8) Re encrypt the boot blob with the new ap boot sub keys
 * 9) Write the boot blob to the flash
 * 10) Wipe the buffers along the process when not needed anymore
 * 
 * @param token replacement token buffer
 * @param component_id_in new component id that goes in
 * @param component_id_out old component id that goes out
 */
void attempt_replace(char token[REPLACEMENT_TOKEN_BUF_LEN], uint32_t component_id_in, uint32_t component_id_out){

    defense_lockout_start();
    
    boot_blob_page_t boot_page;
    uint8_t replacement_key[CC_ENC_SYM_KEY_LEN] = {0};
    uint8_t *encrypted_ap_boot_root_key = AP_BOOT_ROOT_KEY;
    uint8_t ap_boot_root_key[CC_ENC_SYM_KEY_LEN] = {0};
    uint8_t ap_boot_sub_keys[COMPONENT_CNT][CC_ENC_SYM_KEY_LEN] = {0};
    boot_blob decrypted_boot_blob;

    SECURE_MEMCPY(&boot_page, BOOT_BLOB_FLASH, sizeof(boot_blob_page_t));

    FIPROC_DELAY_WRAP();
    if (duplicate_provisioned_id_check() != SUCCESS_RETURN) {
        // LOCKOUT: Duplicate IDs = corrupted internal state = under attack
        defense_lockout_clear(true);
        print_error("Replace failed\n");
        return;
    }
    
    FIPROC_DELAY_WRAP();
    if (replace_check_if_components_are_provisioned_and_legal(component_id_in, component_id_out) != SUCCESS_RETURN){
        defense_lockout_clear(false);
        print_error("Replace failed\n");
        return;
    }

    // Redundant check to improve FI resistance
    FIPROC_DELAY_WRAP();
    if (replace_check_if_components_are_provisioned_and_legal(component_id_in, component_id_out) != SUCCESS_RETURN){
        defense_lockout_clear(false);
        print_error("Replace failed\n");
        return;
    }


    FIPROC_DELAY_WRAP();

    cc_kdf_rt(replacement_key, (void *) token);

    if (cc_decrypt_symmetric(ap_boot_root_key, encrypted_ap_boot_root_key, CC_ENC_SYM_KEY_LEN, replacement_key) != SUCCESS_RETURN){
       crypto_wipe(replacement_key, CC_ENC_SYM_KEY_LEN);
       crypto_wipe(ap_boot_root_key, CC_ENC_SYM_KEY_LEN);

       // LOCKOUT: Wrong RT = under attack
       defense_lockout_clear(true);
       print_error("Replace failed\n");
       crypto_wipe(ap_boot_root_key, CC_ENC_SYM_KEY_LEN);
       return;
    }

    crypto_wipe(replacement_key, CC_ENC_SYM_KEY_LEN);

    compute_ap_boot_sub_keys(ap_boot_sub_keys, ap_boot_root_key, boot_page.provisioned_ids);

    if (decrypt_boot_blob(&decrypted_boot_blob, ap_boot_sub_keys) != SUCCESS_RETURN) {
        crypto_wipe(ap_boot_root_key, CC_ENC_SYM_KEY_LEN);
        for (int i = 0; i < COMPONENT_CNT; i++) {
            crypto_wipe(ap_boot_sub_keys[i], CC_ENC_SYM_KEY_LEN);
        }

        // LOCKOUT: Failed decryption = under attack
        defense_lockout_clear(true);
        print_error("Replace failed\n");
        for(int i = 0; i < COMPONENT_CNT; i++) {
            crypto_wipe(ap_boot_sub_keys[i], CC_ENC_SYM_KEY_LEN);
        }

        return;
    }

    replace_and_sort_provisioned_ids(component_id_in, component_id_out, boot_page.provisioned_ids);

    compute_ap_boot_sub_keys(ap_boot_sub_keys, ap_boot_root_key, boot_page.provisioned_ids);

    encrypt_boot_blob(boot_page.encrypted_boot_blob, &decrypted_boot_blob, ap_boot_sub_keys);

    crypto_wipe(ap_boot_root_key, CC_ENC_SYM_KEY_LEN);

    for (int i = 0; i < COMPONENT_CNT; i++) {
        crypto_wipe(ap_boot_sub_keys[i], CC_ENC_SYM_KEY_LEN);
    }

    SEC_ASSERT(MXC_FLC_PageErase((uint32_t) BOOT_BLOB_FLASH) == SUCCESS_RETURN);
    SEC_ASSERT(MXC_FLC_Write((uint32_t) BOOT_BLOB_FLASH, sizeof(boot_blob_page_t), (void *) &boot_page) == SUCCESS_RETURN);

    defense_lockout_clear(false);
    print_success("Replace\n");
}

/**
 * @brief Attest a component if the pin is correct
 * 
 * @param pin pin
 * @param component_id component id
 */
void attempt_attest(char pin[ATTESTATION_PIN_LEN], uint32_t component_id)  {
    if(attest_component(pin,component_id) != SUCCESS_RETURN){
        print_error("Attest Failed\n");
    }
    else{
        print_success("Attest\n");
    }
}

/********************************* AP LOGIC END ***********************************/

/*********************************** MAIN *************************************/


/**
 * @brief Accepts input and calls the corresponding handler function
 */
void accept_and_parse_commands(void) {
    char buf[CMD_BUF_LEN] = {0};

    while (1) {
        fiproc_load_pool();
        rng_pool_update();
        recv_input("Enter Command: ", buf, CMD_BUF_LEN, false);

        // Execute requested command
        if (!strcmp(buf, "list")) {

            scan_components();

        } else if (!strcmp(buf, "boot")) {

            defense_lockout_start();
            attempt_boot();

            // LOCKOUT: We only reach this point if boot fails = under attack
            defense_lockout_clear(true);

        } else if (!strcmp(buf, "replace")) {

            char token[CMD_BUF_LEN] = {0};
            recv_input("Enter token: ", token, CMD_BUF_LEN, true);
            
            uint32_t component_id_in = 0;
            uint32_t component_id_out = 0;

            recv_input("Component ID In: ", buf, CMD_BUF_LEN, true);
            if(read_hex(buf, CMD_BUF_LEN, &component_id_in) != SUCCESS_RETURN){
                print_error("Invalid ID\n");
                continue;
            }

            recv_input("Component ID Out: ", buf, CMD_BUF_LEN, true);
            if(read_hex(buf, CMD_BUF_LEN, &component_id_out) != SUCCESS_RETURN){
                print_error("Invalid ID\n");
                continue;
            }

            attempt_replace(token, component_id_in, component_id_out);

        } else if (!strcmp(buf, "attest")) {


            char pin[CMD_BUF_LEN] = {0};
            recv_input("Enter pin: ", pin, CMD_BUF_LEN, true);

            // Check that PIN is read correctly
            print_debug("Pin Accepted!\n");

            uint32_t component_id;
            recv_input("Component ID: ", buf, CMD_BUF_LEN, true);

            if(read_hex(buf, CMD_BUF_LEN, &component_id) != SUCCESS_RETURN){
                print_error("Invalid ID\n");
                continue;
            }

            attempt_attest(pin, component_id);

        }
        crypto_wipe(buf, CMD_BUF_LEN);
    }
}

/**
 * @brief Entry point for the application processor
 * 
 * @return int - Should NEVER RETURN
 */
int main() {
    // Cortex-M4 supports 8 regions.
    // All of them must be explicitly configured before the MPU is enabled.

    // Lower half of flash
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(0, 0x10000000), // to 0x1008_0000 (512KiB)
        // Allow execution, read-only
        ARM_MPU_RASR(0, ARM_MPU_AP_PRO, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_512KB)
    );
    // Normal SRAM space (excluding POST_BOOT_CODE area)
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(1, 0x20000000), // to 0x2002_0000 (128KB)
        // No-execute, read-write, disable 0x2000_0000-0x2000_8000 (POST_BOOT_CODE and .flashprog)
        ARM_MPU_RASR(1, ARM_MPU_AP_PRIV, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000011, ARM_MPU_REGION_SIZE_128KB)
    );
    // Peripheral space
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(2, 0x40000000), // to 0x6000_0000 (512MB)
        // No-execute, read-write
        ARM_MPU_RASR(1, ARM_MPU_AP_PRIV, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_512MB)
    );
    // Executable SRAM for POST_BOOT_CODE,
    // set to read-only/execute after decryption
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(3, 0x20000000), // to 0x2000_4000 (16KiB)
        // No-execute, read-write
        ARM_MPU_RASR(1, ARM_MPU_AP_PRIV, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_16KB)
    );
    // Executable SRAM for flashprog
    ARM_MPU_SetRegion(
        ARM_MPU_RBAR(4, 0x20004000), // to 0x2000_6000 (8KiB)
        // Execute, read-only
        ARM_MPU_RASR(0, ARM_MPU_AP_PRO, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000, ARM_MPU_REGION_SIZE_8KB)
    );
    ARM_MPU_ClrRegion(5);
    ARM_MPU_ClrRegion(6);
    ARM_MPU_ClrRegion(7);

    ARM_MPU_Enable(MPU);

    // Initialize hardware
    hardware_init();

    // Initialize SysTick
    tick_init();

    // Setup Flash
    NVIC_DisableIRQ(FLC0_IRQn);
    MXC_FLC_DisableInt(MXC_F_FLC_INTR_DONEIE | MXC_F_FLC_INTR_AFIE);
    MXC_ICC_Enable(MXC_ICC0);

    // Initialize board link interface
    sec_link_init();

    // Initialize RNG
    rng_init();

    // Load the FI prot RNG
    fiproc_load_pool();

    // Initialize defense lockout timer
    // This resumes a 5s delay if the board lost power
    // while previously processing a sensitive command
    defense_lockout_init();

    FIPROC_DELAY_WRAP();

    // LED purple to indicate AP
    LED_On(LED1);
    LED_Off(LED2);
    LED_On(LED3);

    print_info("Application Processor Started\n");

    // Handle commands forever
    accept_and_parse_commands();

    // HCF: We should never return from the accept_and_parse_commands
    // infinite loop, unless a fault occurs
    HALT_AND_CATCH_FIRE();
}

/*********************************** MAIN END *************************************/
