/**
 * @file "handshake.c"
 * @author Kevin Marquis
 * @brief Simple TLS Handshake API Implementation
 * @date 2024
 */
#define DEBUG 0

#define WOLFSSL_CMAC

#include "error.h"
#include "handshake.h"
#include "board_link.h"
#include "host_messaging.h"
#include "mxc_delay.h"
#include "wolfssl/wolfssl/options.h"
#include "wolfssl/wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/dh.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include <stdint.h>
#include <string.h>
#include <math.h>

pcg32_random_t test_rand;



/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Generates a random unsigned integer using TRNG.
 * 
 *  @returns A random unsigned integer
*/
unsigned int my_rng_seed_gen(void){
    return trng_gen_uint();
}

/** @brief Generates a block of bytes using TRNG.
 * 
 * @return 0 if successful.
*/
int my_rng_gen_block(unsigned char* output, unsigned int sz){
    MXC_TRNG_Random(output, sz);
    return 0;
}

/** @brief Verifies an RSA signature using SHA256 hash.
 * 
 *  @param msg A pointer to a buffer containing the signed message.
 *  @param msg_len The length of the signed message in bytes.
 *  @param sig A pointer to a buffer containing the message signature.
 *  @param sig_len The length of the signature in bytes.
 *  @param pubkey A pointer to an RsaKey struct containing the public key
 *      that shall be used to verify the signature.
 * 
 * @return 0 upon success, -1 upon failure, or -2 upon another error.
 * 
*/
int verify_rsa_signature(const uint8_t * msg, int msg_len, const uint8_t * sig, int sig_len, RsaKey * pubkey){
    int ret, dec_sig_len = 128;
    Sha256 sha256;
    uint8_t hash[SHA256_DIGEST_SIZE], decrypted_sig[128];

    #if DEBUG
    print_debug("Entered verify_rsa_signature\n");
    #endif

    ret = wc_InitSha256(&sha256);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to initialize SHA256 context.  Returned %d\n");
        #endif
        return -2;
    }
    ret = wc_Sha256Update(&sha256, msg, msg_len);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to add data to SHA256 context.  Returned %d\n");
        #endif
        return -2;
    }
    ret = wc_Sha256Final(&sha256,  hash);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to compute SHA256 hash.  Returned %d\n");
        #endif
        return -2;
    }
    #if DEBUG
    print_debug("Successfully generated hash.\n");
    #endif

    ret = wc_RsaSSL_Verify(sig, sig_len, decrypted_sig, dec_sig_len, pubkey);
    if (ret <= 0){
        #if DEBUG
        print_error("Failed to verify message! Returned %d\n", ret);
        #endif
        return -1;
    }
    #if DEBUG
    print_debug("Successfully decrypted signature\n");
    #endif

    ret = memcmp(hash, decrypted_sig, ret);
    #if DEBUG
    if (ret != 0){
        print_error("Failed to verify signature!\n");
    }
    else{
        print_info("Successfully verified signature!\n");
    }
    #endif

    return ret;
}

/** @brief Sends a large buffer of data over I2C.
 * 
 *  @param addr The I2C address of the recipient.
 *  @param buf A pointer to a buffer containing the data to be sent.
 *  @param len The length of the data in bytes.
 * 
 *  @return 0 upon success, negative if error.
*/
int send_large_packet(i2c_addr_t addr, const uint8_t * buf, int len){
    uint8_t TX_BUF[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t RX_BUF[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t packet_count, send_fail = 0;
    unsigned int max_packet_count;
    unsigned int remaining_bytes = len;
    int idx = 0, ret;
    large_io_packet* pkt = (large_io_packet*) TX_BUF;
    acknowledge_packet * reply = (acknowledge_packet*) RX_BUF;

    #if DEBUG
    print_debug("Attempting to send a large packet of %d bytes to device addr %d\n", len, addr);
    #endif

    max_packet_count = (len / LARGE_IO_MSG_SIZE) + 1;
    if (max_packet_count > 255 || max_packet_count == 0){
        #if DEBUG
        print_error("Packet too large/small!  Large packets must range in size from %d to %d bytes.\n", 0, (255 * LARGE_IO_MSG_SIZE));
        #endif
        return -1;
    }

    #if DEBUG
    print_debug("Neccessary packets: %d\n", max_packet_count);
    #endif

    packet_count = (uint8_t) max_packet_count; //Downcast packet count after checking size

    while (packet_count > 0){
        pkt->opcode = MASTER_SEND_LARGE;
        pkt->packet_count = packet_count;
        if (packet_count > 1){
            pkt->packet_size = LARGE_IO_MSG_SIZE; //make sure to add a bounds checking on receive end.
        }
        else{
            pkt->packet_size = remaining_bytes % LARGE_IO_MSG_SIZE;
        }

        memcpy(pkt->msg, &buf[idx], pkt->packet_size);

        ret = send_packet(addr, MAX_I2C_MESSAGE_LEN - 1, TX_BUF);
        if (ret == SUCCESS_RETURN){
            #if DEBUG
            print_debug("Packet Successfully Sent!\n");
            #endif
        }
        else{
            #if DEBUG
            print_debug("Packet was not sent successfully.  Returned: %d\n", ret);
            #endif
            return ret;
        }

        ret = poll_and_receive_packet(addr, RX_BUF);
        if (ret == ERROR_RETURN) {
            return ERROR_RETURN;
        }
        //Check for client confirmation:
        if (reply->read_bytes != pkt->packet_size){
            #if DEBUG
            print_error("Clint did not read full packet!\n");
            #endif
            send_fail = 1;
        }

        packet_count -= 1;

        if (reply->expected_packets != packet_count){
            #if DEBUG
            print_error("Client expecting too many packets!\n");
            #endif
            send_fail = 1;
        }

        idx += pkt->packet_size;
        remaining_bytes -= pkt->packet_size;
        #if DEBUG
        print_debug("Resetting I/O Buffers\n");
        #endif
        for (int i = 0; i < MAX_I2C_MESSAGE_LEN; i++){
            TX_BUF[i] = 0;
            RX_BUF[i] = 0;
        }
    }

    if (send_fail == 0){
        return len;
    }
    //error occured in sending/acknowledgement
    return -1;
}

/** @brief Receives a large buffer of data over I2C.
 * 
 *  @param addr The I2C address of the sender.
 *  @param buf A pointer to a buffer to store the received data in.
 *  @param max_buf_len The size of the buffer in bytes.
 * 
 *  @return 0 upon success, negative upon error.
*/
int receive_large_packet(i2c_addr_t addr, uint8_t * buf, int max_buf_len){
    uint8_t TX_BUF[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t RX_BUF[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t packet_count;
    int idx = 0, packet_size, ret;

    large_io_packet* pkt = (large_io_packet*) RX_BUF;
    acknowledge_packet * reply = (acknowledge_packet*) TX_BUF;
    io_packet* command = (io_packet*) TX_BUF;

    #if DEBUG
    print_debug("Attempting to receive a large packet from client addr %d.\n", addr);
    #endif

    do {
        
        command->opcode = MASTER_RECEIVE_LARGE;

        #if DEBUG
        print_debug("Sending data request to client...\n");
        #endif

        //Send a data request to I2C Slave
        ret = send_packet(addr, MAX_I2C_MESSAGE_LEN, TX_BUF);
        if (ret != 0){
            #if DEBUG
            print_debug("Failed to send packet request!\n");
            #endif
        }

        #if DEBUG
        print_debug("Now awaiting packet...\n");
        #endif

        //Receive a packet
        ret = poll_and_receive_packet(addr, RX_BUF);
        if (ret == ERROR_RETURN) {
            return ERROR_RETURN;
        }
        #if DEBUG
        print_debug("Got a packet of size %d!\n", ret);
        print_hex(RX_BUF, MAX_I2C_MESSAGE_LEN);
        #endif        

        packet_count = pkt->packet_count - 1;
        packet_size = pkt->packet_size;

        #if DEBUG
        print_debug("Received a packet of size %d\n", packet_size);
        print_debug("Expecting %d more packets\n", packet_count);
        #endif

        //Save packet to buffer
        if (packet_size + idx <= max_buf_len){
            memcpy(&buf[idx], pkt->msg, packet_size);
        }
        else{
            //Bail out if slave is sending too much data.
            #if DEBUG
            print_error("RX Buffer is full! Packet Size = %d, idx = %d\n", packet_size, idx);
            #endif
            return -1;
        }

        idx += packet_size;

        #if DEBUG
        print_debug("Read in %d bytes from RX Buffer.\n", pkt->packet_size);
        #endif

        //Send acknowledgement
        reply->expected_packets = packet_count;
        reply->read_bytes = packet_size;

        ret = send_packet(addr, sizeof(acknowledge_packet), TX_BUF);
        if (ret == SUCCESS_RETURN){
            #if DEBUG
            print_debug("Acknowledgement Successfully Sent!\n"); //Apparently necessary for this function to work.
            #endif
        }
        else{
            #if DEBUG
            print_debug("Acknowledgement was not sent successfully.  Returned: %d\n", ret);
            #endif
            return ret;
        }

        //Reset buffers for next packet
        #if DEBUG
        print_debug("Resetting I/O Buffers\n");
        #endif
        for (int i = 0; i < MAX_I2C_MESSAGE_LEN; i++){
            TX_BUF[i] = 0;
            RX_BUF[i] = 0;
        }

    //Continue while Slave still has packets to send
    } while (packet_count > 0);


    return idx; //total bytes read
}

/** @brief Conducts a TLS handshake over I2C.
 * 
 * @param target_addr The address of the device to perform the handshake with.
 * @param handshake_ctx A pointer to a tls_record structure to store data into.
 * 
 * @return 0 upon success.  Negative if error.
*/
int handshake_lite(i2c_addr_t target_addr, tls_key * handshake_ctx){
    char ERROR_MSG[] = "HANDSHAKE FAILED";
    RsaKey ca_pub_key;
    WC_RNG rng;
    ecc_key server_priv, client_pub;
    wc_Sha256 sha;

    uint8_t client_random[RANDOM_SIZE], client_pub_key_der[PUB_KEY_MAX_SZ], client_pub_key_sig[PUB_SIG_LEN], server_random[RANDOM_SIZE];
    uint8_t transcript_mac_verify[AES_BLOCK_SIZE], session_key[SESSION_KEY_MAX_SIZE], transcript[TRANSCRIPT_MAX_LEN + AES_BLOCK_SIZE] = {0}, client_transcript[SHA256_DIGEST_SIZE];
    uint8_t client_transcript_mac[SHA256_DIGEST_SIZE], transcript_mac[AES_BLOCK_SIZE], serv_pub_key[100], client_pub_key[100], serv_pub_key_enc[128], client_pub_key_enc[128];
    uint8_t secret[32], initial_transcript[TRANSCRIPT_MAX_LEN] = {0};

    uint8_t abort_handshake = 0, send_abort_msg = 1;
    int ret = 0, client_pub_key_len, client_sig_len, serv_pub_key_len, transcript_tail = 0, transcript_mac_sz = AES_BLOCK_SIZE, transcript_mac_verify_sz = AES_BLOCK_SIZE;
    word32 idx = 0, client_pub_key_sz, secretSz = sizeof(secret);

    #if DEBUG
    ret = wolfSSL_Debugging_ON();
    if (ret != 0){
        print_debug("Failed to turn on WolfSSL debug.  Returned %d\n");
    }
    #endif

    //Initialize structs
    ret = wc_InitRng(&rng);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to initialize RNG: %d\n", ret);
        #endif
        abort_handshake = -1;
        goto failure;
    }

    ret = wc_InitRsaKey(&ca_pub_key, 0);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to initialize CA RSA Key structure. Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto failure;
    }
    #if DEBUG
    print_debug("Successfully initialized RSA Key structures.\n");
    #endif

    // Initialize ECC key
    ret = wc_ecc_init(&server_priv); 
    if (ret < 0){
        #if DEBUG
        print_error("Failed to initialize Server ECC Key.  Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_rsa;
    }

    //Initialize Client ECC Key Struct
    ret = wc_ecc_init(&client_pub);
    if (ret < 0){
        #if DEBUG
        print_debug("Failed to initialize Client ECC Key.  Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_rsa_serv_ecc;
    }
    #if DEBUG
    print_debug("Successfully initalized ECC key structures.\n");
    #endif

    ret = wc_InitSha256(&sha);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to initialize SHA256 Struct.  Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_debug("Successfully initialized SHA256 struct.\n");
    #endif

    wc_EccPrivateKeyDecode(DEVICE_KEY, &idx, &server_priv, DEVICE_KEY_DER_LEN);
    if (ret != 0){
        #if DEBUG
        print_error("Error in decoding Server Key. Returned: %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }

    // Pull CA Public Key from On-Device Buffer
    idx = 0;
    ret = wc_RsaPublicKeyDecode(CA_PUB_DER, &idx, &ca_pub_key, CA_PUB_DER_LEN);
    if (ret != 0){
        #if DEBUG
        print_error("Error in decoding CA Key. Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully decoded CA Public Key\n");
    #endif

    //Receive Server Random
    ret = receive_large_packet(target_addr, client_random, RANDOM_SIZE);
    if (ret < RANDOM_SIZE || (strcmp(ERROR_MSG, client_random) == 0)){
        #if DEBUG
        if (ret < RANDOM_SIZE){
            print_error("Failed to receive full Client Random.\n");
        } else if (strcmp(ERROR_MSG, client_random) == 0){
            print_error("Received abort message from client.  Aborting.\n");
        }
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully received Client Random.\n");
    #endif

    //Receive Client Pub Key
    client_pub_key_len = receive_large_packet(target_addr, client_pub_key_der, PUB_KEY_MAX_SZ);
    if (client_pub_key_len < 0 || (strcmp(ERROR_MSG, client_pub_key_der) == 0)){
        #if DEBUG
        if (client_pub_key_len < 0){
            print_error("Failed to receive client public key! Ret = %d\n", client_pub_key_len);
        }else if (strcmp(ERROR_MSG, client_pub_key_der) == 0){
            print_error("Received abort message from client.  Aborting.\n");
        }
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully received Client Public Key.\n");
    #endif

    //Receive Client Signature
    client_sig_len = receive_large_packet(target_addr, client_pub_key_sig, PUB_SIG_LEN);
    if (client_sig_len < 0 || (strcmp(ERROR_MSG, client_pub_key_sig) == 0)){
        #if DEBUG
        if (client_sig_len < 0){
            print_error("Failed to receive client signature! Ret = %d\n", client_sig_len);
        } else if (strcmp(ERROR_MSG, client_pub_key_sig) == 0){
            print_error("Received abort message from client.  Aborting.\n");
        }
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully received Client Signature\n");
    #endif

    //Verify Signature
    ret = verify_rsa_signature(client_pub_key_der, client_pub_key_len, client_pub_key_sig, client_sig_len, &ca_pub_key);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to verify client public key signature!\n");
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully verified client public key.\n");
    #endif

    //Decode Client ECC Public Key
    idx = 0;
    ret = wc_EccPublicKeyDecode(client_pub_key_der, &idx, &client_pub, client_pub_key_len);
    if (ret < 0){
        #if DEBUG
        print_error("Failed to decode client ECC Public Key.  Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully decoded client ECC Public Key.\n");
    #endif

    MXC_TRNG_Random(server_random, RANDOM_SIZE);
    #if DEBUG
    print_debug("Successfully generated server random.\n");
    #endif
    
    //Send Server Random
    ret = send_large_packet(target_addr, server_random, RANDOM_SIZE);
    if (ret < RANDOM_SIZE){
        #if DEBUG
        print_error("Failed to send full server random\n");
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully sent server random.\n");
    #endif

    //Send Server Public Key
    ret = send_large_packet(target_addr, DEVICE_PUB_DER, DEVICE_PUB_DER_LEN);
    if (ret < DEVICE_PUB_DER_LEN){
        #if DEBUG
        print_error("Failed to send server public key\n");
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully sent server public key.\n");
    #endif

    //Send Server Signature
    ret = send_large_packet(target_addr, DEVICE_SIG, DEVICE_SIG_LEN);
    if (ret < DEVICE_SIG_LEN){
        #if DEBUG
        print_error("Failed to send server public key signature\n");
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully sent server signature.\n");
    #endif

    //Generate shared secret from Server ECC Key and Client ECC Public Key
    ret = wc_ecc_shared_secret(&server_priv, &client_pub, secret, &secretSz);
    if ( ret != 0 ) {
        #if DEBUG
        print_error("Failed to generate shared ECC secret.  Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully generated shared ECC secret.\n");
    #endif

    //Compute session key with KDF
    // Session_Key = KDF(Shared Secret, Client_Random, Server_Random)
    ret = wc_HKDF(WC_SHA256, secret, secretSz, client_random, RANDOM_SIZE, server_random, RANDOM_SIZE, session_key, SESSION_KEY_MAX_SIZE);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to generate session key with HKDF.  Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully generated session key with HKDF.\n");
    #endif

    //Compute Transcript
    //Transcript = {SERVER_RANDOM||CLIENT_RANDOM}
    if ((transcript_tail + RANDOM_SIZE) > TRANSCRIPT_MAX_LEN){
        #if DEBUG
        print_error("Failed too add Client Random to transcript.\n");
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    memcpy(initial_transcript + transcript_tail, client_random, RANDOM_SIZE);
    transcript_tail += RANDOM_SIZE;

    if ((transcript_tail + RANDOM_SIZE) > TRANSCRIPT_MAX_LEN){
        #if DEBUG
        print_error("Failed to Add Server Random to transcript.\n");
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    memcpy(initial_transcript + transcript_tail, server_random, RANDOM_SIZE);
    transcript_tail += RANDOM_SIZE;

    #if DEBUG
    print_info("Successfully built initial transcript.\n");
    #endif

    //Use CMAC for additional speed in handshake
    ret = wc_AesCmacGenerate(transcript_mac, &transcript_mac_sz, initial_transcript, sizeof(initial_transcript), session_key, SESSION_KEY_MAX_SIZE);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to generate CMAC.  Returned %d.\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }

    #if DEBUG
    print_info("Successfully computed transcript HMAC.\n");

    //Print out Transcript MAC for debug help.
    printf("\n\n\n--------------TRANSCRIPT MAC--------------\n");
    print_hex(transcript_mac, sizeof(transcript_mac));
    printf("\n--------------TRANSCRIPT MAC END--------------\n");
    #endif

    //Send transcript MAC
    ret = send_large_packet(target_addr, transcript_mac, transcript_mac_sz);
    if (ret != transcript_mac_sz){
        #if DEBUG
        print_error("Failed to send full transcript MAC to client.  Returned %d.\n");
        #endif
        abort_handshake = -1;
        send_abort_msg = 0;
        goto cleanup_all;
    }

    if ((transcript_tail + transcript_mac_sz) > (TRANSCRIPT_MAX_LEN + AES_BLOCK_SIZE)){
        #if DEBUG
        print_error("Failed to Add Server MAC to transcript\n");
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }

    memcpy(transcript, initial_transcript, TRANSCRIPT_MAX_LEN);
    memcpy(transcript + transcript_tail, transcript_mac, AES_BLOCK_SIZE);
    transcript_tail += AES_BLOCK_SIZE;

    //Verify Client Transcript
    ret = wc_AesCmacGenerate(transcript_mac_verify, &transcript_mac_verify_sz, transcript, sizeof(transcript), session_key, SESSION_KEY_MAX_SIZE);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to generate verification CMAC.  Returned %d.\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }

    #if DEBUG
    print_info("Computed CMAC verification transcript.\n");
    #endif

    //Receive Client transcript MAC
    ret = receive_large_packet(target_addr, client_transcript_mac, AES_BLOCK_SIZE);
    if (ret < 0){
        #if DEBUG
        print_error("Failed to receive client's transcript MAC.  Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        send_abort_msg = 0;
        goto cleanup_all;
    }
    if (strcmp(ERROR_MSG, client_transcript_mac) == 0){
        #if DEBUG
        print_error("Received abort message from client.  Aborting.\n");
        #endif
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully received client transcript and MAC.\n");
    #endif



    //Verify MAC
    ret = memcmp(client_transcript_mac, transcript_mac_verify, AES_BLOCK_SIZE);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to verify client transcript MAC.\n");
        #endif
        abort_handshake = -1;
        send_abort_msg = 0;
        goto cleanup_all;
    }
    #if DEBUG
    print_debug("Transcripts match!\n");
    #endif


cleanup_all:
    #if DEBUG
    print_debug("Entering Cleanup\n");
    #endif

    //Free ECC Key Structd
    ret = wc_ecc_free(&client_pub);
    if (ret < 0){
        #if DEBUG
        print_debug("Failed to free Client ECC Key.  Returned %d\n", ret);
        #endif
        return -1;
    }
    #if DEBUG
    print_debug("Successfully freed client ECC key.\n");
    #endif

cleanup_rsa_serv_ecc:
    ret = wc_ecc_free(&server_priv); 
    if (ret < 0){
        #if DEBUG
        print_error("Failed to free Server ECC Key.  Returned %d\n", ret);
        #endif
    }
    #if DEBUG
    print_debug("Successfully freed client ECC key.\n");
    #endif

cleanup_rsa:
    ret = wc_FreeRsaKey(&ca_pub_key);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to free CA RSA Key structure. Returned %d\n", ret);
        #endif
    }
    #if DEBUG
    print_debug("Successfully freed CA RSA Key structure.\n");
    #endif

    //Handshake Successful
    //Copy key, transcript to struct (For Communication)
    if (abort_handshake == 0){
        #if DEBUG
        print_debug("Handshake Successful!\n");
        #endif

        if (handshake_ctx != NULL){
            memcpy(handshake_ctx->key, session_key, SESSION_KEY_SIZE);
            handshake_ctx->key_len = SESSION_KEY_SIZE;
            #if DEBUG
            print_info("Copied data to handshake context struct\n");
            printf("key\n");
            print_hex(session_key, SESSION_KEY_SIZE);
            print_hex(handshake_ctx->key, 16);
            #endif
        }
        return 0;
    }

failure:
    //Handshake Failed.  Send message to Client to Disconnect.
    #if DEBUG
    print_error("Handshake Failed.\n");
    #endif
    if (send_abort_msg){
        send_large_packet(target_addr, ERROR_MSG, strlen(ERROR_MSG));
    }
    return -1;
}

/** @brief Sends data over I2C using a secure symmetric key.
 * 
 *  @param target_addr The I2C of the recipient.
 *  @param enc_ctx A pointer to an initialized AES structure containing the key.
 *  @param handshake_ctx A pointer to a tls_key struct containing the shared key.
 *  @param buf A pointer to a buffer containing the data to be sent.
 *  @param len The length of the buffer in bytes.
 * 
 *  @return 0 upon success, -1 if message to large, -2 if encryption error, or -3 if I/O error. 
*/
int secure_send_lite(i2c_addr_t target_addr, Aes * enc_ctx, tls_key * handshake_ctx, uint8_t * buf, int len){
    //Encrypt buffer with session key from handshake
    if (len > 248){
        #if DEBUG
        print_error("Message too large.\n");
        #endif
        return -1;
    }

    int ret;
    int len_dif = (16 - (len % 16)); //if 16B input, len_diff = 16
    int out_buf_len = len + len_dif;
    uint8_t plaintext[out_buf_len];
    uint8_t ciphertext[out_buf_len];
    uint8_t pt_mac[SHA256_DIGEST_SIZE];
    Hmac hmac;

    //Generate MAC
    ret = wc_HmacSetKey(&hmac, WC_SHA256, handshake_ctx->key, handshake_ctx->key_len);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to initialize HMAC struct.  Returned %d.\n", ret);
        #endif
        return -2;
    }
    ret = wc_HmacUpdate(&hmac, buf, len);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to add data to HMAC struct.  Returned %d\n", ret);
        #endif
        return -2;
    }
    ret = wc_HmacFinal(&hmac, pt_mac);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to compute final HMAC.  Returned %d.\n", ret);
        #endif
        return -2;
    }

    //Pad message (PKCS padding)
    memcpy(plaintext, buf, len);
    for (uint8_t i = 0; i < len_dif; i++){
        plaintext[len + i] = len_dif;
    }

    ret = wc_AesCbcEncrypt(enc_ctx, ciphertext, plaintext, out_buf_len);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to encrypt message.  Returned %d\n", ret);
        #endif
        return -2;
    }

    //Send encrypted buffer
    ret = send_large_packet(target_addr, ciphertext, out_buf_len);
    if (ret != out_buf_len){
        #if DEBUG
        print_error("Failed to send ciphertext\n");
        #endif
        return -3;
    }

    ret = send_large_packet(target_addr, pt_mac, SHA256_DIGEST_SIZE);
    if (ret != out_buf_len){
        #if DEBUG
        print_error("Failed to send MAC\n");
        #endif
        return -3;
    }

    //success
    return 0;
}

/** @brief Receives data over I2C using a secure symmetric key.
 * 
 *  @param target_addr The I2C of the sender.
 *  @param enc_ctx A pointer to an initialized AES structure containing the key.
 *  @param handshake_ctx A pointer to a tls_key struct containing the shared key.
 *  @param buf A pointer to a buffer for the received data to be stored in.
 *  @param len The length of the buffer in bytes.
 * 
 *  @return Number of bytes received upon success, -1 if I/O error, -2 if decryption error, 
 *      or -3 if buffer is too small.
*/
int secure_receive_lite(i2c_addr_t target_addr, Aes * dec_ctx, tls_key * handshake_ctx, uint8_t * buf, int len){
    int ret, ciphertext_len, mac_len;
    uint8_t pad_len, plaintext[SECURE_IO_MAX_LEN] = {0}, ciphertext[SECURE_IO_MAX_LEN] = {0}, mac[SHA256_DIGEST_SIZE], pt_mac[SHA256_DIGEST_SIZE];
    Hmac hmac;
    int plaintext_len = 0;

    //Receive encrypted buffer
    ciphertext_len = receive_large_packet(target_addr, ciphertext, SECURE_IO_MAX_LEN);
    if (ciphertext_len <= 0){
        #if DEBUG
        print_error("Failed to receive ciphertext.\n");
        #endif
        return -1;
    }

    //Receive MAC
    mac_len = receive_large_packet(target_addr, mac, SECURE_IO_MAX_LEN);
    if (ciphertext_len <= 0){
        #if DEBUG
        print_error("Failed to receive ciphertext.\n");
        #endif
        return -1;
    }

    //Decrypt buffer with session key from handshake
    ret = wc_AesCbcDecrypt(dec_ctx, plaintext, ciphertext, ciphertext_len);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to decrypt ciphertext.  Returned %d\n", ret);
        #endif
        return -2;
    }
    #if DEBUG
    print_debug("Decrypted ciphertext\n");
    #endif

    //unpad (PKCS)
    pad_len = plaintext[ciphertext_len - 1];
    plaintext_len = ciphertext_len - pad_len;
    if (plaintext_len <= len){
        memcpy(buf, plaintext, plaintext_len);
    }
    else{
        #if DEBUG
        print_error("Message too large for buffer.\n");
        #endif
        return -3;
    }
    #if DEBUG
    print_info("Unpadded Message\n");
    #endif

    //Verify MAC
    ret = wc_HmacSetKey(&hmac, WC_SHA256, handshake_ctx->key, handshake_ctx->key_len);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to initialize HMAC struct.  Returned %d.\n", ret);
        #endif
        return -2;
    }
    ret = wc_HmacUpdate(&hmac, buf, plaintext_len);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to add data to HMAC struct.  Returned %d\n", ret);
        #endif
        return -2;
    }
    ret = wc_HmacFinal(&hmac, pt_mac);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to compute final HMAC.  Returned %d.\n", ret);
        #endif
        return -2;
    }
    #if DEBUG
    print_info("Computed MAC\n");
    #endif

    ret = memcmp(pt_mac, mac, SHA256_DIGEST_SIZE);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to verify message MAC.\n");
        #endif
        return -2;
    }
    #if DEBUG
    print_info("Successfully verified MAC.\n");
    #endif

    //success
    return plaintext_len;
}
