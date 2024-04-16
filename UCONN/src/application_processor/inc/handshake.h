/**
 * @file "handshake.c"
 * @author Kevin Marquis
 * @brief Simple TLS Handshake API Header
 * @date 2024
 */
#ifndef ECTF_HANDSHAKE_H
#define ECTF_HANDSHAKE_H

#include "error.h"
#include "handshake.h"
#include "board_link.h"
#include "host_messaging.h"
#include "certs.h"
#include "wolfssl/wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/aes.h"

#include <stdint.h>
#include <string.h>
/******************************** MACRO DEFINITIONS ********************************/
#define SESSION_KEY_SIZE 16
#define TRANSCRIPT_MAX_LEN (2 * RANDOM_SIZE)
#define TEMP_KEY_MAX_LEN 256
#define SESSION_KEY_MAX_SIZE 16
#define RANDOM_SIZE 128
#define PUB_KEY_MAX_SZ 200
#define RSA_CIPHERTEXT_SIZE 128
#define PUB_SIG_LEN 128
#define LARGE_IO_MSG_SIZE 252
#define SECURE_IO_MAX_LEN 255

/******************************** STRUCT DEFINITIONS ********************************/
typedef struct { uint64_t state;  uint64_t inc; } pcg32_random_t;
typedef struct { uint8_t opcode; uint8_t params[MAX_I2C_MESSAGE_LEN-1]; } io_packet;
typedef struct { uint8_t opcode; uint8_t packet_count; uint8_t packet_size; uint8_t msg[MAX_I2C_MESSAGE_LEN-3]; } large_io_packet;
typedef struct { uint8_t expected_packets; uint8_t read_bytes; } acknowledge_packet;
typedef struct { uint8_t key[SESSION_KEY_SIZE]; int key_len; } tls_key;
typedef enum { MASTER_SENDING, MASTER_RECEIVING, MASTER_SEND_LARGE, MASTER_RECEIVE_LARGE } io_master_cmd;

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Generates a random unsigned integer using TRNG.
 * 
 *  @returns A random unsigned integer
*/
unsigned int my_rng_seed_gen(void);

/** @brief Generates a block of bytes using TRNG.
 * 
 * @return 0 if successful.
*/
int my_rng_gen_block(unsigned char* output, unsigned int sz);

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
int verify_rsa_signature(const uint8_t * msg, int msg_len, const uint8_t * sig, int sig_len, RsaKey * pubkey);

/** @brief Sends a large buffer of data over I2C.
 * 
 *  @param addr The I2C address of the recipient.
 *  @param buf A pointer to a buffer containing the data to be sent.
 *  @param len The length of the data in bytes.
 * 
 *  @return 0 upon success, negative if error.
*/
int send_large_packet(i2c_addr_t addr, const uint8_t * buf, int len);

/** @brief Receives a large buffer of data over I2C.
 * 
 *  @param addr The I2C address of the sender.
 *  @param buf A pointer to a buffer to store the received data in.
 *  @param max_buf_len The size of the buffer in bytes.
 * 
 *  @return 0 upon success, negative upon error.
*/
int receive_large_packet(i2c_addr_t addr, uint8_t * buf, int max_buf_len);

/** @brief Conducts a TLS handshake over I2C.
 * 
 * @param target_addr The address of the device to perform the handshake with.
 * @param handshake_ctx A pointer to a tls_key structure to store data into.
 * 
 * @return 0 upon success.  Negative if error.
*/
int handshake_lite(i2c_addr_t target_addr, tls_key * handshake_ctx);

/** @brief Sends data over I2C using a secure symmetric key.
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
int secure_send_lite(i2c_addr_t target_addr, Aes * enc_ctx, tls_key * handshake_ctx, uint8_t * buf, int len);

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
int secure_receive_lite(i2c_addr_t target_addr, Aes * dec_ctx, tls_key * handshake_ctx, uint8_t * buf, int len);
#endif // ECTF_HANDSHAKE_H
