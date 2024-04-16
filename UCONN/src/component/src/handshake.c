/**
 * @file "handshake.c"
 * @author Kevin Marquis
 * @brief Simple TLS Handshake API Implementation
 * @date 2024
 */
#define DEBUG 0

#include "error.h"
#include "handshake.h"
#include "board_link.h"
#include "host_messaging.h"
#include "certs.h"
#include "wolfssl/wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/dh.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"

#include <stdint.h>
#include <string.h>

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
    print_debug("Attempting to verify a signature...\n");
    #endif

    ret = wc_InitSha256(&sha256);
    if (ret == 0) {
        ret = wc_Sha256Update(&sha256, msg, msg_len);
    }
    if (ret == 0)
        ret = wc_Sha256Final(&sha256,  hash);

    ret = wc_RsaSSL_Verify(sig, sig_len, decrypted_sig, dec_sig_len, pubkey);
    if (ret <= 0){
        #if DEBUG
        print_error("Failed to verify message! Ret = %d\n", ret);
        #endif
        return -1;
    }

    ret = memcmp(hash, decrypted_sig, ret);
    #if DEBUG
    if (ret != 0){
        #if DEBUG
        print_error("Failed to verify signature!\n");
        #endif
    }
    #endif

    return ret;
}

/** @brief Sends a large buffer of data over I2C.
 * 
 *  @param buf A pointer to a buffer containing the data to be sent.
 *  @param len The length of the data in bytes.
 * 
 *  @return 0 upon success, negative if error.
*/
int send_large_packet(const uint8_t * buf, int len){
    uint8_t TX_BUF[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t RX_BUF[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t packet_count;
    unsigned int max_packet_count;
    unsigned int remaining_bytes = len;
    int idx = 0, ret;

    
    #if DEBUG
    print_debug("Attempting to send a large packet of %d bytes\n", len);
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
    large_io_packet* pkt = (large_io_packet*) TX_BUF;
    acknowledge_packet * reply = (acknowledge_packet*) RX_BUF;
    io_packet * cmd = (io_packet *) RX_BUF;
    pkt->opcode = MASTER_RECEIVE_LARGE;

    while(1){
        ret = wait_and_receive_packet(RX_BUF);
        if (cmd->opcode != MASTER_RECEIVE_LARGE){
            #if DEBUG
            print_error("Master wants to send!\n");
            #endif
        }
        break;
    }

    while (packet_count > 0){
        pkt->packet_count = packet_count;
        if (packet_count > 1){
            pkt->packet_size = LARGE_IO_MSG_SIZE; //make sure to add a bounds checking on receive end.
        }
        else{
            pkt->packet_size = remaining_bytes % LARGE_IO_MSG_SIZE;
        }
        #if DEBUG
        print_debug("Packet Data Size: %d\n", pkt->packet_size);
        #endif

        memcpy(pkt->msg, &buf[idx], pkt->packet_size);

        #if DEBUG
        print_hex(TX_BUF, MAX_I2C_MESSAGE_LEN);
        #endif

    send_packet_and_ack(MAX_I2C_MESSAGE_LEN-1, TX_BUF);

    ret = wait_and_receive_packet(RX_BUF);
    if (ret == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    //Check for client confirmation:
    if (reply->read_bytes != pkt->packet_size){
        #if DEBUG
        print_error("Server did not read full packet!: %d != %d\n", reply->read_bytes, pkt->packet_size);
        #endif
        return -1;
    }

    packet_count -= 1;

    if (reply->expected_packets != packet_count){
        #if DEBUG
        print_error("Server expecting too many packets! %d != %d\n", reply->expected_packets, packet_count);
        #endif
    }

    idx += pkt->packet_size;
    remaining_bytes -= pkt->packet_size;
    MXC_I2C_ClearRXFIFO(I2C_INTERFACE);

    #if DEBUG
    print_debug("Resetting I/O Buffers\n");
    #endif
    for (int i = 0; i < MAX_I2C_MESSAGE_LEN; i++){
        TX_BUF[i] = 0;
        RX_BUF[i] = 0;
    }
    }

    I2C_REGS[RECEIVE_DONE][0] = false;

    return len;
}

/** @brief Receives a large buffer of data over I2C.
 * 
 *  @param buf A pointer to a buffer to store the received data in.
 *  @param max_buf_len The size of the buffer in bytes.
 * 
 *  @return 0 upon success, negative upon error.
*/
int receive_large_packet(uint8_t * buf, int max_buf_len){
    uint8_t TX_BUF[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t RX_BUF[MAX_I2C_MESSAGE_LEN] = {0};
    uint8_t packet_count = 0xFF, bad_packet = 0;
    int idx = 0, packet_size, ret;

    large_io_packet* pkt = (large_io_packet*) RX_BUF;
    acknowledge_packet * reply = (acknowledge_packet*) TX_BUF;

    #if DEBUG
    print_debug("Attempting to receive a large packet...\n");
    #endif

    do {
        #if DEBUG
        print_debug("Awaiting data request...\n");
        #endif
        ret = wait_and_receive_packet(RX_BUF);

        if (pkt->opcode != MASTER_SEND_LARGE){
            #if DEBUG
            print_error("Component is trying to receive, but master wants to receive.\n");
            print_error("Got: %d\n", pkt->opcode);
            #endif
            bad_packet = 1;
        }

        if (!bad_packet){
            #if DEBUG
            print_debug("Got a packet of size %d!\n", ret);
            print_hex(RX_BUF, MAX_I2C_MESSAGE_LEN);
            #endif

            packet_count = pkt->packet_count - 1;
            packet_size = pkt->packet_size;

            #if DEBUG
            print_debug("Got a packet of size %d", packet_size);
            print_debug("%d more packets\n", packet_count);
            #endif

            if (packet_size + idx <= max_buf_len){
                memcpy(&buf[idx], pkt->msg, packet_size);
            }
            else{
                #if DEBUG
                print_error("RX Buffer is full! Packet Size = %d, idx = %d\n", packet_size, idx);
                #endif
                return -1;
            }

            #if DEBUG
            print_debug("Read in %d bytes.  Now sending ackowledgement...\n", pkt->packet_size);
            #endif

            idx += packet_size;

            //Send acknowledgement
            reply->expected_packets = packet_count;
            reply->read_bytes = packet_size;

            send_packet_and_ack(2, TX_BUF); //Can probs shorten message len
            #if DEBUG
            print_debug("Resetting I/O Buffers\n");
            #endif
            for (int i = 0; i < MAX_I2C_MESSAGE_LEN; i++){
                TX_BUF[i] = 0;
                RX_BUF[i] = 0;
            }
        }
    } while (packet_count > 0);

    return idx; //total bytes read
}

/** @brief Conducts a TLS handshake over I2C.
 * 
 * @param target_addr The address of the device to perform the handshake with.
 * @param handshake_ctx A pointer to a tls_key structure to store data into.
 * 
 * @return 0 upon success.  Negative if error.
*/
int handshake_lite(tls_key * handshake_ctx){
    //Function triggered after handshake command was sent.
    char ERROR_MSG[] = "HANDSHAKE FAILED";

    uint8_t client_random[RANDOM_SIZE];
    uint8_t server_random[RANDOM_SIZE];
    uint8_t server_pub_key_der[PUB_KEY_MAX_SZ];
    uint8_t server_pub_key_sig[PUB_SIG_LEN];
    uint8_t initial_transcript[TRANSCRIPT_MAX_LEN] = {0};
    uint8_t transcript[TRANSCRIPT_MAX_LEN + AES_BLOCK_SIZE] = {0};
    uint8_t transcript_mac[AES_BLOCK_SIZE];
    uint8_t client_transcript_mac[AES_BLOCK_SIZE];
    uint8_t server_transcript[SHA256_DIGEST_SIZE];
    uint8_t server_transcript_mac[AES_BLOCK_SIZE];
    uint8_t transcript_mac_verify[AES_BLOCK_SIZE];
    byte serv_pub_key[100], client_pub_key[100], serv_pub_key_enc[128], client_pub_key_enc[128];
    byte secret[32];
    uint8_t session_key[SESSION_KEY_MAX_SIZE];
    uint8_t abort_handshake = 0, send_abort_msg = 1;

    WC_RNG rng;
    RsaKey ca_pub_key;
    ecc_key client_priv, serv_pub;
    wc_Sha256 sha;

    word32 idx = 0, secretSz = sizeof(secret);
    int transcript_tail = 0, ret, server_pub_key_len, server_sig_len;
    int transcript_mac_sz = AES_BLOCK_SIZE, transcript_mac_verify_sz = AES_BLOCK_SIZE;

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
        print_error("Failed to initialize Server RSA Key structure. Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto failure;
    }

    ret = wc_ecc_init(&serv_pub);
    if (ret < 0){
        #if DEBUG
        print_error("Failed to initialize Server ECC Key.  Returned %d\n", ret);
        #endif
        goto cleanup_rsa;
    }

    ret = wc_ecc_init(&client_priv); // initialize key
    if (ret < 0){
        #if DEBUG
        print_debug("Failed to initialize Client ECC Key.  Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_rsa_serv_ecc;
    }


    ret = wc_InitSha256(&sha);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to initialize SHA256 Struct.  Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }

    wc_EccPrivateKeyDecode(DEVICE_KEY, &idx, &client_priv, DEVICE_KEY_DER_LEN);
    if (ret != 0){
        #if DEBUG
        print_error("Error in decoding Server Key. Returned: %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }

    idx = 0;
    ret = wc_RsaPublicKeyDecode(CA_PUB_DER, &idx, &ca_pub_key, CA_PUB_DER_LEN);
    if (ret != 0){
        #if DEBUG
        print_error("Error in decoding CA Key. Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    } 

    //Generate Client Random (TRNG)
    #if DEBUG
    print_debug("Generating client random...\n");
    #endif

    MXC_TRNG_Random(client_random, RANDOM_SIZE);
    #if DEBUG
    print_debug("Successfully generated client random.\n");

    print_hex(client_random, RANDOM_SIZE);

    print_debug("Attempting to send client random...\n");
    #endif

    //Send Client Random
    ret = send_large_packet(client_random, RANDOM_SIZE);
    if (ret < RANDOM_SIZE){
        #if DEBUG
        print_error("Failed to send full client random\n");
        #endif
        return -1;
    }

    #if DEBUG
    print_debug("Successfully sent client random!\n");

    print_debug("Attempting to send client certificate...\n");
    #endif

    //Send Client Certificate
    ret = send_large_packet(DEVICE_PUB_DER, DEVICE_PUB_DER_LEN);
    if (ret < DEVICE_PUB_DER_LEN){
        #if DEBUG
        print_error("Failed to send client public key\n");
        #endif
        return -1;
    }

    ret = send_large_packet(DEVICE_SIG, DEVICE_SIG_LEN);
    if (ret < DEVICE_SIG_LEN){
        #if DEBUG
        print_error("Failed to send client public key signature\n");
        #endif
        return -1;
    }

    //Receive Server Random
    ret = receive_large_packet(server_random, RANDOM_SIZE);
    if (ret < RANDOM_SIZE || (strcmp(ERROR_MSG, server_random) == 0)){
        #if DEBUG
        if (ret < RANDOM_SIZE){
            print_error("Failed to receive full server Random.\n");
        } else if (strcmp(ERROR_MSG, client_random) == 0){
            print_error("Received abort message from server.  Aborting.\n");
        }
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }

    //Receive Server Certificate
    server_pub_key_len = receive_large_packet(server_pub_key_der, PUB_KEY_MAX_SZ);
    if (server_pub_key_len < 0 || (strcmp(ERROR_MSG, server_pub_key_der) == 0)){
        #if DEBUG
        if (server_pub_key_len < 0){
            print_error("Failed to receive server public key! Ret = %d\n", server_pub_key_len);
        }else if (strcmp(ERROR_MSG, server_pub_key_der) == 0){
            print_error("Received abort message from server.  Aborting.\n");
        }
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully received Server Public Key.\n");
    #endif

    server_sig_len = receive_large_packet(server_pub_key_sig, PUB_SIG_LEN);
    if (server_sig_len < 0 || (strcmp(ERROR_MSG, server_pub_key_sig) == 0)){
        #if DEBUG
        if (server_sig_len < 0){
            print_error("Failed to receive server signature! Ret = %d\n", server_sig_len);
        } else if (strcmp(ERROR_MSG, server_pub_key_sig) == 0){
            print_error("Received abort message from server.  Aborting.\n");
        }
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }

    ret = verify_rsa_signature(server_pub_key_der, server_pub_key_len, server_pub_key_sig, server_sig_len, &ca_pub_key);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to verify server public key signature!\n");
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully verified server public key.\n");
    #endif

    idx = 0;
    ret = wc_EccPublicKeyDecode(server_pub_key_der, &idx, &serv_pub, server_pub_key_len);
    if (ret < 0){
        #if DEBUG
        print_error("Failed to decode server ECC Public Key.  Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    #if DEBUG
    print_info("Successfully decoded server ECC Public Key.\n");
    #endif

    // receive public key, and initialise into pub
    ret = wc_ecc_shared_secret(&client_priv, &serv_pub, secret, &secretSz);
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
    // Session_Key = KDF(Temporary Key, Client_Random||Server_Random)
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
    #if DEBUG
    print_debug("Attempting to build transcript...\n");
    #endif

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
        print_error("Failed to Add Server Random to transcript\n");
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    memcpy(initial_transcript + transcript_tail, server_random, RANDOM_SIZE);
    transcript_tail += RANDOM_SIZE;
    #if DEBUG
    print_info("Successfully built initial transcript.\n");
    #endif

    #if DEBUG
    print_info("Successfully built initial transcript.\n");
    #endif

    //Transcript = {SERVER_CERT||CLIENT_CERT||SERVER_RANDOM||CLIENT_RANDOM}
    //Compute MAC
    //Use CMAC for additional speed in handshake
    ret = wc_AesCmacGenerate(transcript_mac_verify, &transcript_mac_verify_sz, initial_transcript, sizeof(initial_transcript), session_key, SESSION_KEY_MAX_SIZE);
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
    print_hex(transcript_mac_verify, sizeof(transcript_mac_verify));
    printf("\n--------------TRANSCRIPT MAC END--------------\n");
    #endif

    ret = receive_large_packet(server_transcript_mac, AES_BLOCK_SIZE);
    if (ret < 0){
        #if DEBUG
        print_error("Failed to receive server's transcript MAC.  Returned %d\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }

    //Verify Server Transcript
    ret = memcmp(server_transcript_mac, transcript_mac_verify, AES_BLOCK_SIZE);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to verify server transcript MAC.\n");
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }
    
    //Compute and Send Client Transcript
    if ((transcript_tail + AES_BLOCK_SIZE) > (TRANSCRIPT_MAX_LEN + AES_BLOCK_SIZE)){
        #if DEBUG
        print_error("Failed to Add Server MAC to transcript\n");
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }

    memcpy(transcript, initial_transcript, TRANSCRIPT_MAX_LEN);
    memcpy(transcript + transcript_tail, server_transcript_mac, AES_BLOCK_SIZE);
    transcript_tail += AES_BLOCK_SIZE;

    #if DEBUG
    print_info("Successfully received server transcript MAC.\n");
    #endif

    ret = wc_AesCmacGenerate(client_transcript_mac, &transcript_mac_sz, transcript, sizeof(transcript), session_key, SESSION_KEY_MAX_SIZE);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to generate verification CMAC.  Returned %d.\n", ret);
        #endif
        abort_handshake = -1;
        goto cleanup_all;
    }

    //Send Transcript MAC
    ret = send_large_packet(client_transcript_mac, transcript_mac_sz);
    if (ret != transcript_mac_sz){
        #if DEBUG
        print_error("Failed to send full transcript MAC to server\n");
        #endif
        return -1;
    }

    #if DEBUG
    print_info("Sent CMAC verification transcript.\n");
    #endif

cleanup_all:
    #if DEBUG
    print_debug("Entering Cleanup\n");
    #endif

    //Free ECC Key Structd
    ret = wc_ecc_free(&client_priv);
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
    ret = wc_ecc_free(&serv_pub); 
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
        send_large_packet(ERROR_MSG, strlen(ERROR_MSG));
    }
    return -1;
}

/** @brief Sends data over I2C using a secure symmetric key.
 * 
 *  @param target_addr The I2C of the recipient.
 *  @param enc_ctx A pointer to an initialized AES structure containing the key.
 *  @param buf A pointer to a buffer containing the data to be sent.
 *  @param len The length of the buffer in bytes.
 * 
 *  @return 0 upon success, -1 if message to large, -2 if encryption error, or -3 if I/O error. 
*/
int secure_send_lite(Aes * enc_ctx, tls_key * handshake_ctx, uint8_t * buf, int len){
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

    for (int i = 0; i < out_buf_len; i++){
        plaintext[i] = 0;
        ciphertext[i] = 0;
    }

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
        plaintext[len + i] = (uint8_t) len_dif;
    }

    ret = wc_AesCbcEncrypt(enc_ctx, ciphertext, plaintext, out_buf_len);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to encrypt message.  Returned %d\n", ret);
        #endif
        return -2;
    }

    //Send encrypted buffer
    ret = send_large_packet(ciphertext, out_buf_len);
    if (ret != out_buf_len){
        #if DEBUG
        print_error("Failed to send ciphertext\n");
        #endif
        return -3;
    }

    ret = send_large_packet(pt_mac, SHA256_DIGEST_SIZE);
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
 *  @param buf A pointer to a buffer for the received data to be stored in.
 *  @param len The length of the buffer in bytes.
 * 
 *  @return Number of bytes received upon success, -1 if I/O error, -2 if decryption error,
 *      or -3 if buffer is too small. 
*/
int secure_receive_lite(Aes * dec_ctx, tls_key * handshake_ctx, uint8_t * buf, int len){
    int ret, mac_len;
    uint8_t pad_len, plaintext[SECURE_IO_MAX_LEN], ciphertext[SECURE_IO_MAX_LEN], mac[SHA256_DIGEST_SIZE], pt_mac[SHA256_DIGEST_SIZE];
    Hmac hmac;
    word32 ciphertext_len, plaintext_len;

    //Receive encrypted buffer
    ciphertext_len = receive_large_packet(ciphertext, SECURE_IO_MAX_LEN);
    if (ciphertext_len <= 0){
        #if DEBUG
        print_error("Failed to receive ciphertext.\n");
        #endif
        return -1;
    }

    //Receive MAC
    mac_len = receive_large_packet(mac, SECURE_IO_MAX_LEN);
    if (ciphertext_len <= 0){
        #if DEBUG
        print_error("Failed to receive ciphertext.\n");
        #endif
        return -1;
    }
    #if DEBUG
    print_debug("Received ciphertext and MAC.\n");
    #endif

    //Decrypt buffer with session key from handshake
    ret = wc_AesCbcDecrypt(dec_ctx, plaintext, ciphertext, ciphertext_len);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to decrypt ciphertext.  Returned %d\n", ret);
        #endif
        return -2;
    }

    //unpad (PKCS)
    pad_len = plaintext[ciphertext_len - 1];
    plaintext_len = ciphertext_len - pad_len;
    if (plaintext_len <= len){
        memcpy(buf, plaintext, plaintext_len);
    }
    else{
        #if DEBUG
        print_error("Message too large for buffer.  Received %d, Available Space: %d\n", plaintext_len, len);
        #endif
        return -3;
    }

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
    print_debug("Successfully computed MAC.\n");
    #endif

    ret = memcmp(pt_mac, mac, SHA256_DIGEST_SIZE);
    if (ret != 0){
        #if DEBUG
        print_error("Failed to verify message MAC.\n");
        #endif
        return -2;
    }

    //success
    return plaintext_len;
}
