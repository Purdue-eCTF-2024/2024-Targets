/**
 * @file "simple_hw_aes.h"
 * @author Kevin Marquis
 * @brief Simplified Hardware Accelerated AES API Header
 * @date 2024
 */

#include <stdint.h>
#include "aes.h"
#include "mxc_device.h"
#include "host_messaging.h"

#define MXC_AES_SINGLEBLOCK_DATA_LENGTH 4

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts a block of plaintext using built-in hardware accelerated AES.
 * 
 * @param plaintext A pointer to a buffer of length 16B containing the
 *          plaintext to encrypt
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 * 
 * @return 0 on success, other non-zero for other error
 */
int enc_aes_128_block(uint32_t * plaintext, uint32_t * ciphertext, uint8_t * key);

/** @brief Decrypts a block of ciphertext using a HW Accelerated AES.
 *
 * @param ciphertext A pointer to a buffer, containing 1 block of ciphertext
 *           to decrypt.
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length 16B where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, other non-zero for other error
 */
int dec_aes_128_block(uint32_t * plaintext, uint32_t * ciphertext, uint8_t * key);

/** @brief Demonstrates the encryption and decryption of a single block of plaintext.
 *
 * @return  None
 */
void aes_demo();