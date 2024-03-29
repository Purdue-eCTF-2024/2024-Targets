#ifndef CRYPTO_WOLFSSL_H
#define CRYPTO_WOLFSSL_H

#include "secure_buffer.h"

#define MAX_KEY_ADVANCE_ROUNDS 2
#define KEY_LEN_BYTES 32

/**
 * Fill a buffer slice with bytes from the TRNG.
 */
void rand_bytes(buf_u8 buf);
/**
 * @brief A key that can be ratcheted forward.
 *
 * Represents a key that is updated after every use. Once a round is advanced
 * forward, it cannot be moved backward.
 */
typedef struct derived_key {
    uint8_t key[KEY_LEN_BYTES];
    uint32_t round;
} derived_key;
/**
 * Initialize a derived key by combining a master key and a nonce.
 *
 * @param master_key A single pre-shared key that is used as a base.
 * @param nonce A randomly generated nonce shared at runtime.
 */
derived_key initialize_derived_key(const buf_u8 master_key, const buf_u8 nonce);
/**
 * Ratchet a derived key forward until it reaches the specified round. Panics if
 * the key is already ahead of the round, or if round is too big.
 *
 * @param k Key to advance forward.
 * @param round Round to advance key to.
 *
 * @return `true` on success.
 */
bool advance_key(derived_key *k, uint32_t round);
/**
 * @brief Pad and encrypt a buffer slice.
 *
 * @param buf Buffer slice to encrypt.
 * @param key Key to use to encrypt. The current state of this key is used.
 * @param buf_out Buffer to write encrypted output to.
 *
 * @return Number of bytes written to `buf_out`.
 *
 * Pad and encrypt a buffer slice using a randomized initialization vector. This
 * does not advance the derived_key.
 */
uint32_t encrypt_buf(const buf_u8 buf, const derived_key *key, buf_u8 buf_out);
/**
 * @brief Decrypt a buffer slice.
 *
 * @param buf Buffer slice to decrypt.
 * @param key Key to use to encrypt. The current state of this key is used.
 * @param buf_out Buffer to write decrypted output to.
 *
 * @return Number of bytes written to `buf_out`.
 *
 * Decrypt a properly buffer slice output by `encrypt_buf`. This does not
 * advance the derived_key.
 */
uint32_t decrypt_buf(const buf_u8 buf, const derived_key *key, buf_u8 buf_out);
/**
 * @brief Decrypt a buffer slice.
 *
 * @param buf Buffer slice to decrypt.
 * @param key Key to use to encrypt. The current state of this key is used.
 * @param buf_out Buffer to write decrypted output to.
 *
 * @return Number of bytes written to `buf_out`.
 *
 * Decrypt a properly buffer slice output by `encrypt_buf`. This does not
 * advance the derived_key.
 */
uint32_t hmac(const buf_u8 buf, const derived_key *key, buf_u8 buf_out);

// int sha3_256(const buf_u8 buf, buf_u8 buf_out);

#endif
