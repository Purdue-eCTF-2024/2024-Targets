/**
 * @file component.c
 * @author Plaid Parliament of Pwning
 * @brief Implements component functions
 * 
 * Implements the functional and security requirements for the component functions -for booting, providing attestation data and communicating via secure send/receive
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"

#include "flc.h"
#include "icc.h"

#include "hardware_init.h"
#include "ticks.h"
#include "encrypted.h"
#include "util.h"
#include "crypto_wrappers.h"
#include "comm_types.h"
#include "crypto_wrappers.h"
#include "secure_snd_rcv.h"
#include "rng.h"
#include "comm_link.h"
#include "sec_link.h"
#include "fiproc.h"

#include "resources.h"
#include "boot_blob.h"
#include "libc_mu.h"

#include <string.h>

/**
 * @brief Linker defined variables for encrypted code sections
 */
extern uint8_t _code_encrypted, _code_decrypted, _ecode_decrypted;

/**
 * @brief Secure send/receive sub key for this component
 */
uint8_t secure_send_sub_key[CC_ENC_SYM_KEY_LEN];

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_req_boot_key(void);
void process_boot(void);
void process_ping(void);
void process_validate(void);
void process_attest(void);
/********************************* FUNCTION DECLARATIONS END **********************************/

/********************************* GLOBAL VARIABLES **********************************/

/**
 * @brief receive buffer for secure receive
 */
uint8_t receive_buffer[COMM_MAX_MSG_LEN];

/**
 * @brief receive buffer for secure send
 */
uint8_t transmit_buffer[COMM_MAX_MSG_LEN];

/**
 * @brief Sequence number for the secure send/receive communication
 */
uint32_t SEQ_NUM = 0;

/********************************* GLOBAL VARIABLES END **********************************/

/******************************* POST BOOT FUNCTIONALITY *********************************/

/**
 * @brief Send a packet to AP
 * 
 * Intended to be used INTERNALLY within this file
 * Validates sender/recv id, seq num
 * 
 * @param secure_msg message to be sent to component
 * @param address I2C address of component
 * @return SUCCESS_RETURN if everything succeeds, ERROR_RETURN on error
*/
int internal_secure_send(secure_msg_t* secure_msg){

    // Derive component address for sent message metadata
    uint8_t comp_address = component_id_to_i2c_address(COMPONENT_ID);
    
    // Prepare the secure send message
    secure_msg->sender_id = comp_address;
    secure_msg->receiver_id = AP_ID;
    secure_msg->seq_num = SEQ_NUM;

    // Buffer to hold the encrypted message
    uint8_t cipher_secure_msg[sizeof(secure_msg_t) + CC_ENC_SYM_METADATA_LEN];
    
    // Generate 24 bytes of nonce for AEAD Encryption
    FIPROC_DELAY_WRAP();
    uint8_t rng_bytes[24];
    rng_generate_bulk_fast(rng_bytes, sizeof(rng_bytes));

    // Ensure buffer is clear, then encrypt the message with secure send subkey
    crypto_wipe(cipher_secure_msg, sizeof(cipher_secure_msg));
    FIPROC_DELAY_WRAP();
    cc_encrypt_symmetric(cipher_secure_msg, (uint8_t*)secure_msg, sizeof(secure_msg_t), secure_send_sub_key, rng_bytes);
    
    FIPROC_DELAY_WRAP();
    // Send encrypted packet to ap
    if (sec_link_respond(cipher_secure_msg, sizeof(cipher_secure_msg)) != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }

    // Increment SEQ num
    SEQ_NUM++;

    //Everything has completed successfully
    return SUCCESS_RETURN;
}

/**
 * @brief Receive a packet from specified component
 * 
 * Intended to be used INTERNALLY within this file
 * Validates sender/recv id, seq num
 * 
 * @param secure_msg  message received, decrypted and passed by reference to caller
 * @param address I2C address of component
 * @return SUCCESS_RETURN if everything succeeds, ERROR_RETURN on error
*/
int internal_secure_receive(secure_msg_t* secure_msg){
    // Derive component address for received message metadata verification
    uint8_t comp_address = component_id_to_i2c_address(COMPONENT_ID);

    // Receive the encrypted message from the AP
    uint8_t cipher_secure_msg[sizeof(secure_msg_t) + CC_ENC_SYM_METADATA_LEN];
    if(sec_link_receive_and_send_ack(cipher_secure_msg, sizeof(cipher_secure_msg)) != sizeof(cipher_secure_msg)){
        return ERROR_RETURN;
    }

    FIPROC_DELAY_WRAP();

    // Attempt to decrypt the received message
    if(cc_decrypt_symmetric((uint8_t*)secure_msg, cipher_secure_msg, sizeof(secure_msg_t), secure_send_sub_key) != SUCCESS_RETURN){
        // Decryption failed
        return ERROR_RETURN;
    }

    FIPROC_DELAY_WRAP();

    // Validate the seq num
    if(secure_msg->seq_num != SEQ_NUM){
        // Someone has tampered with the encryption or attempted a replay
        return ERROR_RETURN;
    }

    FIPROC_DELAY_WRAP();
    SEC_ASSERT(((volatile secure_msg_t*) secure_msg)->seq_num == SEQ_NUM);

    // Verify sender_id and receiver_id
    if(secure_msg->sender_id != AP_ID){
        // Someone has tampered with the encryption or attempted a replay
        return ERROR_RETURN;
    } 

    FIPROC_DELAY_WRAP();
    SEC_ASSERT(((volatile secure_msg_t*) secure_msg)->sender_id == AP_ID);

    // Verify message was intended for the Component
    if(secure_msg->receiver_id != comp_address){
        // Someone has tampered with the encryption or attempted a replay
        return ERROR_RETURN;
    } 

    FIPROC_DELAY_WRAP();
    SEC_ASSERT(((volatile secure_msg_t*) secure_msg)->receiver_id == comp_address);

    // Increment SEQ num
    SEQ_NUM++;

    //Everything has completed successfully
    return SUCCESS_RETURN;
}

/**
 * @brief Secure Send 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
 * 
 * @param buffer pointer to data to be send
 * @param len size of data to be sent 
*/
void secure_send(uint8_t* buffer, uint8_t len) {
    fiproc_load_pool();
    rng_pool_update();

    if (len > MAX_MSG_LEN) {
        // HCF: The caller has violated the function's contract,
        // this can only be caused by a hardware fault.
        HALT_AND_CATCH_FIRE();
    }

    /* Step 1: AP sends a REQ-TO-RECEIVE message to the Component */

    secure_msg_t secure_msg = { 0 };

    while (1) {
        // Ensure bytes are clear before use
        crypto_wipe(&secure_msg, sizeof(secure_msg));

        FIPROC_DELAY_WRAP();

        // Receive Request to receive from AP
        while (FAILED(internal_secure_receive(&secure_msg))) {
            MXC_Delay(RETRY_DELAY_RX);
            FIPROC_DELAY_WRAP();
        }

        FIPROC_DELAY_WRAP();

        /* Step 2: Component sends message to AP after verification */

        // Verify expected message is received
        if (secure_msg.message_type != COMM_AP_REQ_SECURE_RECEIVE) {
            MXC_Delay(RETRY_DELAY_RX);
            continue;
        }

        // Generate Message Struct
        secure_msg_t secure_msg_send = { 0 };
        secure_msg_send.nonce = secure_msg.nonce;
        secure_msg_send.message_type = COMM_COMP_RESP_SECURE_MSG;
        // Making sure expected length is passed to function
        secure_msg_send.message_len = len;
        FIPROC_DELAY_WRAP();
        SECURE_MEMCPY(secure_msg_send.message, buffer, len);

        while (FAILED(internal_secure_send(&secure_msg_send))) {
            MXC_Delay(RETRY_DELAY_TX);
            FIPROC_DELAY_WRAP();
        }

        fiproc_ranged_delay();

        return;
    }
}

/**
 * @brief Secure Receive
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * @return int: number of bytes received, negative if error
*/
int secure_receive(uint8_t* buffer) {
    fiproc_load_pool();
    rng_pool_update();

    /* Step 1: Receive REQ-TO-SEND packet from the AP */
    // Receive req-to-send message from the AP
    secure_msg_t secure_msg = { 0 };

    while (1) {
        FIPROC_DELAY_WRAP();
        crypto_wipe(&secure_msg, sizeof(secure_msg));
        while (FAILED(internal_secure_receive(&secure_msg))) {
            MXC_Delay(RETRY_DELAY_RX);
            FIPROC_DELAY_WRAP();
        }

        FIPROC_DELAY_WRAP();

        // Verify the type of the message received
        if (secure_msg.message_type != COMM_AP_REQ_SECURE_SEND) {
            MXC_Delay(RETRY_DELAY_RX);
            FIPROC_DELAY_WRAP();
            continue;
        }

        FIPROC_DELAY_WRAP();
        if (secure_msg.message_len != 0) {
            MXC_Delay(RETRY_DELAY_RX);
            FIPROC_DELAY_WRAP();
            continue;
        }

        break;
    }

    /* Step 2: Send a nonce to AP as a challenge */
    uint32_t nonce;
    rng_generate_bulk_fast((uint8_t*)&nonce, sizeof(nonce));

    // Prepare the nonce packet to be sent
    secure_msg_t secure_msg_nonce = { 0 };
    secure_msg_nonce.message_type = COMM_COMP_RESP_SECURE_NONCE;
    secure_msg_nonce.nonce = nonce;
    
    FIPROC_DELAY_WRAP();

    // Attempt sending the nonce packet
    while (FAILED(internal_secure_send(&secure_msg_nonce))) {
        MXC_Delay(RETRY_DELAY_TX);
        FIPROC_DELAY_WRAP();
    }

    /* Step 3: Receive the message the AP wants to send */
    // Attempt receiving the actual message from the AP
    secure_msg_t secure_msg_data = { 0 };

    volatile int fi_valid = 0;

    while (1) {
        crypto_wipe(&secure_msg_data, sizeof(secure_msg_data));
        FIPROC_DELAY_WRAP();
        while (FAILED(internal_secure_receive(&secure_msg_data))) {
            MXC_Delay(RETRY_DELAY_RX);
            FIPROC_DELAY_WRAP();
        }

        // Validate the message len
        if (secure_msg_data.message_len > MAX_MSG_LEN) {
            // The message len is more than expected. Unacceptable.
            MXC_Delay(RETRY_DELAY_RX);
            continue;
        } 

        FIPROC_DELAY_WRAP();

        SEC_ASSERT(((volatile secure_msg_t) secure_msg_data).message_len <= MAX_MSG_LEN);
        fi_valid = (((volatile secure_msg_t) secure_msg_data).message_len <= MAX_MSG_LEN); 

        // Validate the received message
        if (secure_msg_data.message_type != COMM_AP_REQ_SECURE_MSG) {
            // If the message type doesn't match... 
            // go back to listening to the message from the AP
            MXC_Delay(RETRY_DELAY_RX);
            continue;
        }

        FIPROC_DELAY_WRAP();

        SEC_ASSERT(((volatile secure_msg_t) secure_msg_data).message_type == COMM_AP_REQ_SECURE_MSG);
        fi_valid &= (((volatile secure_msg_t) secure_msg_data).message_type == COMM_AP_REQ_SECURE_MSG); 

        // Validate the nonce
        if (secure_msg_data.nonce != nonce) {
            MXC_Delay(RETRY_DELAY_RX);
            continue;
        } 

        FIPROC_DELAY_WRAP();

        SEC_ASSERT(((volatile secure_msg_t) secure_msg_data).nonce == nonce);
        fi_valid &= (((volatile secure_msg_t) secure_msg_data).nonce == nonce); 

        // Copy the received message into the buffer sent by the post-boot code
        SECURE_MEMCPY(buffer, secure_msg_data.message, secure_msg_data.message_len);

        // Prepare and send the final ACK to the AP
        secure_msg_t secure_msg_ack = { 0 };
        secure_msg_ack.message_type = COMM_COMP_RESP_SECURE_ACK;
        if (internal_secure_send(&secure_msg_ack) != SUCCESS_RETURN) {
            // Go back to listening for the message from the AP, if ACK wasn't successful
            MXC_Delay(RETRY_DELAY_TX);
            FIPROC_DELAY_WRAP();
            continue;
        }

        FIPROC_DELAY_WRAP();

        SEC_ASSERT(fi_valid == 1);
        fiproc_ranged_delay();
        SEC_ASSERT(fi_valid == 1);

        // Return the num of bytes received on success
        return secure_msg_data.message_len;
    }
}

/******************************* POST BOOT FUNCTIONALITY END *********************************/

/******************************* FUNCTION DEFINITIONS *********************************/


/**
 * @brief Wipes the boot blob
 * 
 * @param blob boot blob
 */
void crypto_wipe_boot_blob(boot_blob blob) {
    crypto_wipe((void *)blob.comp_code_key, CC_ENC_SYM_KEY_LEN);
    crypto_wipe((void *)blob.secure_send_subkey, CC_ENC_SYM_KEY_LEN);
    crypto_wipe((void *)blob.boot_msg, BOOT_MSG_LEN);
}

/**
 * @brief Decrypts Boot Blob using ap_boot_sub_keys
 * 
 * @param blob output buffer for decrypted boot blob
 * @param comp_boot_sub_key component boot sub key
 * @return 0 on success, negative on error
 */
int decrypt_boot_blob(boot_blob* blob, uint8_t comp_boot_sub_key[CC_ENC_SYM_KEY_LEN]) {
    boot_blob_page_t *boot_blob_page = BOOT_BLOB_FLASH;
    if (cc_decrypt_symmetric((void *)blob, boot_blob_page->encrypted_boot_blob, sizeof(boot_blob), comp_boot_sub_key)) {
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}

/**
 * @brief Decrypt post boot code
 * 
 * @param comp_code_key component code key
 * @return 0 on success, negative on error
 */
int decrypt_post_boot_code(uint8_t comp_code_key[CC_ENC_SYM_KEY_LEN]){
    size_t text_sz = (&_ecode_decrypted) - (&_code_decrypted);
    if (cc_decrypt_symmetric(&_code_decrypted, &_code_encrypted, text_sz,  comp_code_key)){
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
 * @brief Handle a transaction from the AP
 * 
 * This function NEVER RETURNS
 */
void process_cmds_forever() {
    while (1) {
        int ret = sec_link_receive_and_send_ack(receive_buffer, COMM_MAX_MSG_LEN);
        if (ret < 0) {
            continue;
        }
        fiproc_load_pool();
        rng_pool_update();
        comm_meta_t* command = (comm_meta_t*) receive_buffer;
        uint32_t msg_type = command->msg_type;

        // Output to application processor dependent on command received
        switch (msg_type) {
            case COMM_AP_REQ_BOOT_KEY:
                process_req_boot_key();
                break;

            case COMM_AP_REQ_COMP_BOOT:
                process_boot();
                break;

            case COMM_AP_REQ_AD:
                process_attest();
                break;

            case COMM_AP_REQ_LIST_PING:
                process_ping();
                break;

            default:
                break;
          }
        crypto_wipe((void*)receive_buffer, COMM_MAX_MSG_LEN);
    }

    // HCF: The while(1) loop above should never be able to return
    // unless there is a hardware fault
    HALT_AND_CATCH_FIRE();
}

/**
 * @brief Proess request for the boot key
 * 
 * The AP requested component_boot_key
 */
void process_req_boot_key() {
    comm_comp_resp_boot_key_t send_packet;
    send_packet.msg_info.msg_type = COMM_COMP_RESP_BOOT_KEY;
    SECURE_MEMCPY(send_packet.ap_boot_sub_key, AP_BOOT_SUBKEY, CC_ENC_SYM_KEY_LEN);
    sec_link_respond((void *)&send_packet, sizeof(send_packet));
    crypto_wipe(send_packet.ap_boot_sub_key, CC_ENC_SYM_KEY_LEN);
}

/**
 * @brief  Process request for booting component 
 * 
 * 1) Decrypt boot blob
 * 2) Decrypt post boot code
 * 3) Boot!!
 */
void process_boot() {
    comm_ap_req_comp_boot_t *boot_cmd = (comm_ap_req_comp_boot_t *) (receive_buffer); 
    boot_blob decrypted_boot_blob;

    if (decrypt_boot_blob(&decrypted_boot_blob, boot_cmd->comp_boot_sub_key)) {
        return;
    }

    if (decrypt_post_boot_code(decrypted_boot_blob.comp_code_key)){
        crypto_wipe_boot_blob(decrypted_boot_blob);
        return;
    }

    // Sending component boot msg
    comm_comp_resp_boot_msg_t send_packet;
    send_packet.msg_info.msg_type = COMM_COMP_RESP_BOOT_MSG;
    SECURE_MEMCPY(send_packet.boot_msg, decrypted_boot_blob.boot_msg, BOOT_MSG_LEN);
    sec_link_respond((void *)&send_packet, sizeof(send_packet));
    SECURE_MEMCPY(secure_send_sub_key, decrypted_boot_blob.secure_send_subkey, CC_ENC_SYM_KEY_LEN);

    crypto_wipe_boot_blob(decrypted_boot_blob);

    rng_pool_update();
    boot();
}

/**
 * @brief Process request for a ping to the component
 *  
 * The AP pinged us. Respond with a pong
 */
void process_ping() {
    comm_comp_resp_list_pong_t* pong = (comm_comp_resp_list_pong_t*) transmit_buffer;
    pong->msg_info.msg_type = COMM_COMP_RESP_LIST_PONG;
    pong->comp_id = COMPONENT_ID;
    sec_link_respond(transmit_buffer, sizeof(comm_comp_resp_list_pong_t));
    crypto_wipe((void*)transmit_buffer, COMM_MAX_MSG_LEN);
}


/**
 * @brief Respond with the attestation data per request from AP
*/
void process_attest() {
    sec_link_respond((uint8_t *)&ENCRYPTED_ATT_DATA, COMM_MAX_MSG_LEN);
}


/******************************* FUNCTION DEFINITIONS END *********************************/

/*********************************** MAIN *************************************/

/**
 * @brief The entry point for the component
 * 
 * @return SHOULD NEVER RETURN
 */
int main(void) {
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

    // Initialize RNG
    rng_init();

    // Load the FI prot RNG
    fiproc_load_pool();

    // LED teal to indicate Component
    LED_Off(LED1);
    LED_On(LED2);
    LED_On(LED3);
    
    // Initialize link to the AP
    sec_link_init();

    // Small delay to allow peripherals to warm up
    MXC_Delay(100000);

    process_cmds_forever();

    // HCF: process_cmds_forever() should never return
    // unless there is a hardware fault
    HALT_AND_CATCH_FIRE();
}

/*********************************** MAIN END *************************************/
