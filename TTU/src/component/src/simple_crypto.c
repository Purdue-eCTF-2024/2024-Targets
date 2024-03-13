/**
 * @file "simple_crypto.c"
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

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>

/******************************** FUNCTION PROTOTYPES ********************************/
/** 
 * @brief Generate a random IV
 * 
 * @param iv: uint8_t*, A pointer to a buffer of length len to write the generated IV to
 * @param len: size_t, The length of the IV to generate
 *
 * @return int, 0 on success, non-zero for other error
 */
int generate_iv(uint8_t *iv, size_t len) {
    WC_RNG rng;
    wc_InitRng(&rng);
    int ret = wc_RNG_GenerateBlock(&rng, iv, len);
    wc_FreeRng(&rng);
    return ret;
}

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
int create_encrypted_packet(uint8_t *plaintext, size_t plaintext_len, uint8_t *key, uint8_t *packet) {
    int total_len = 1 + IV_SIZE + TAG_SIZE + plaintext_len; // Total Length = 1 byte for length + IV_SIZE + TAG_SIZE + plaintext_len
    byte iv[IV_SIZE]; // IV is 12 bytes
    generate_iv(iv, IV_SIZE); // Generate a random IV and store it in iv
    int ret = wc_ChaCha20Poly1305_Encrypt(key, iv, NULL, 0, (byte *)plaintext, plaintext_len, packet + CIPHERTEXT_OFFSET, packet + AUTH_TAG_OFFSET);

    // Copy the total length and IV into the packet (the encrypt function will handle the ciphertext and tag)
    memcpy(packet, &total_len, 1); // Copying total length as the first byte
    memcpy(packet + IV_OFFSET, iv, IV_SIZE); // Copying IV into the packet
    return ret;
}

/** @brief Decrypt an encrypted packet
 * 
 * @param packet: uint8_t*, A pointer to a buffer containing the encrypted packet
 * @param key: uint8_t*, A pointer to a buffer of length KEY_SIZE containing the key to use for decryption
 * @param plaintext: uint8_t*, A pointer to a buffer of at least total_len - 1 - IV_SIZE - TAG_SIZE bytes to write the decrypted plaintext to
 *
 * @return int, 0 on success, non-zero for other error
 */
int decrypt_encrypted_packet(uint8_t *packet, uint8_t *key, uint8_t *plaintext) {
    int total_len = packet[0];
    int plaintext_len = total_len - 1 - IV_SIZE - TAG_SIZE; // Excluding length, iv, and tag
    byte iv[IV_SIZE];
    byte ciphertext[plaintext_len];
    byte tag[TAG_SIZE];
    memcpy(iv, packet + IV_OFFSET, IV_SIZE);
    memcpy(ciphertext, packet + CIPHERTEXT_OFFSET, plaintext_len);
    memcpy(tag, packet + AUTH_TAG_OFFSET, TAG_SIZE);
    int ret = wc_ChaCha20Poly1305_Decrypt(key, iv, NULL, 0, ciphertext, plaintext_len, tag, (byte *)plaintext);
    plaintext[plaintext_len] = '\0'; // Null-terminate the plaintext
    return ret;
}

/** 
 * @brief Hashes arbitrary-length data
 *
 * @param data: uint8_t*, A pointer to a buffer of length len containing the data to be hashed
 * @param len: size_t, The length of the plaintext to encrypt
 * @param hash_out: uint8_t*, A pointer to a buffer of length HASH_SIZE where the resulting hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int sha256_hash(void *data, size_t len, uint8_t *hash_out) {
    return wc_Sha256Hash((uint8_t *)data, len, hash_out);
}