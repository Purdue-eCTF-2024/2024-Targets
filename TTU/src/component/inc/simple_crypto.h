/**
 * @file "simple_crypto.h"
 * @author Ben Janis, TTU
 * @brief Implements AES and SHA256 encryption and decryption for the 2024 eCTF
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/chacha20_poly1305.h"
#include "wolfssl/wolfcrypt/random.h"

/******************************** MACRO DEFINITIONS ********************************/
#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16

#define LENGTH_OFFSET 0 // 0
#define IV_OFFSET 1 // 1
#define AUTH_TAG_OFFSET 13 // 0 + 1 + IV_SIZE
#define CIPHERTEXT_OFFSET 29 // 0 + 1 + IV_SIZE + TAG_SIZE

#define HASH_SIZE SHA256_DIGEST_SIZE

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Generate a random IV
 * 
 * @param iv: uint8_t*, A pointer to a buffer of length len to write the generated IV to
 * @param len: size_t, The length of the IV to generate
 *
 * @return int, 0 on success, non-zero for other error
 */
int generate_iv(uint8_t *iv, size_t len);

// Packets will follow the following format:
// +-----------------------------------------+
// | Total Length |     IV     |  Auth. Tag  |
// +--------------+------------+-------------+
// |     1 Byte   |  12 Bytes  |  16 Bytes   |
// +-----------------------------------------+
// |              Ciphertext                 |
// |                 ...                     |
// +-----------------------------------------+

/** @brief Create an encrypted packet
 * 
 * @param plaintext: uint8_t*, A pointer to a buffer of length plaintext_len containing the plaintext to encrypt
 * @param plaintext_len: size_t, The length of the plaintext to encrypt
 * @param key: uint8_t*, A pointer to a buffer of length KEY_SIZE containing the key to use for encryption
 * @param packet: uint8_t*, A pointer to a buffer of at least plaintext_len + IV_SIZE + TAG_SIZE + 1 bytes to write the encrypted packet to
 *
 * @return int, 0 on success, non-zero for other error
 */
int create_encrypted_packet(uint8_t *plaintext, size_t plaintext_len, uint8_t *key, uint8_t *packet);

/** @brief Decrypt an encrypted packet
 * 
 * @param packet: uint8_t*, A pointer to a buffer containing the encrypted packet
 * @param key: uint8_t*, A pointer to a buffer of length KEY_SIZE containing the key to use for decryption
 * @param plaintext: uint8_t*, A pointer to a buffer of at least total_len - 1 - IV_SIZE - TAG_SIZE bytes to write the decrypted plaintext to
 *
 * @return int, 0 on success, non-zero for other error
 */
int decrypt_encrypted_packet(uint8_t *packet, uint8_t *key, uint8_t *plaintext);

/** 
 * @brief Hashes arbitrary-length data
 *
 * @param data: uint8_t*, A pointer to a buffer of length len containing the data to be hashed
 * @param len: size_t, The length of the plaintext to encrypt
 * @param hash_out: uint8_t*, A pointer to a buffer of length HASH_SIZE where the resulting hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int sha256_hash(void *data, size_t len, uint8_t *hash_out);

#endif
