/**
 * @file crypto_wrappers.c
 * @author Plaid Parliament of Pwning
 * @brief Crypto wrappers over monocypher for a simplified interface
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include <string.h>
#include "crypto_wrappers.h"
#include "monocypher.h"

#include "fiproc.h"
#include "util.h"

#if IS_AP
#include "keys.h"
#else
#include "resources.h"
#endif

/**
 * @brief Wrapper for symmetric encryption
 * 
 * Requires 24 bytes of randomness in the rand_buf
 * Ciphertext will be length+CC_ENC_SYM_METADATA_LEN bytes long
 * Provides authenticated encryption (any tampering will be detected upon decrypt)
 * 
 * @param ciphertext pointer to ciphertext
 * @param plaintext pointer to plaintext
 * @param length length of the plaintext
 * @param sym_key symmteric key
 * @param rand_buf nonce buffer
 */
void cc_encrypt_symmetric(uint8_t *ciphertext, const uint8_t *plaintext, size_t length, const uint8_t *sym_key, const uint8_t *rand_buf) {
    
    // Nonce misuse resistance: hash the plaintext. concat with random nonce, hash again with key.
    uint8_t hash_tmp[CC_NONCE_HASH_LEN];

    cc_hash_internal(hash_tmp, CC_NONCE_HASH_LEN, plaintext, length, rand_buf, CC_NONCE_RAND_LEN, 4);
    FIPROC_DELAY_WRAP();
    cc_hash_internal(hash_tmp, CC_NONCE_HASH_LEN, hash_tmp, CC_NONCE_HASH_LEN, NONCE_KEY, CC_ENC_SYM_KEY_LEN, 4);
    xor_bytes(hash_tmp, rand_buf, CC_NONCE_RAND_LEN);
    FIPROC_DELAY_WRAP();
    SECURE_MEMCPY(ciphertext+16, hash_tmp, CC_NONCE_RAND_LEN);
    crypto_wipe(hash_tmp, sizeof(hash_tmp));
    FIPROC_DELAY_WRAP();
    crypto_lock(ciphertext+0, ciphertext+40, sym_key, ciphertext+16, plaintext, length);
}

/**
 * @brief Wrapper for symmetric decryption
 * 
 * Plaintext will be length bytes long
 * Ciphertext will be length+CC_ENC_SYM_METADATA_LEN bytes long
 * Provides authenticated encryption; 
 * 
 * @param plaintext pointer to plaintext
 * @param ciphertext pointer to ciphertext
 * @param length length of the plaintext
 * @param sym_key symmteric key
 * @return int 0 if decrypt succeeds, -1 if tampering or corruption detected
 */
int cc_decrypt_symmetric(uint8_t *plaintext, const uint8_t *ciphertext, size_t length, const uint8_t *sym_key) {
    // Repeat the operation multiple times to resist attacks
    volatile int res1 = crypto_unlock(plaintext, sym_key, ciphertext+16, ciphertext+0, ciphertext+40, length);
    FIPROC_DELAY_WRAP();
    volatile int res2 = crypto_unlock(plaintext, sym_key, ciphertext+16, ciphertext+0, ciphertext+40, length);
    FIPROC_DELAY_WRAP();
    volatile int res3 = crypto_unlock(plaintext, sym_key, ciphertext+16, ciphertext+0, ciphertext+40, length);
    FIPROC_DELAY_WRAP();

    UTIL_ASSERT(res1 == res2);
    UTIL_ASSERT(res1 == res3);
    UTIL_ASSERT(res2 == res3);
    FIPROC_DELAY_WRAP();
    UTIL_ASSERT(res2 == res3);

    return res1;
}

/**
 * @brief Hash a buffer 
 * 
 * Optionally supports keyed hashing if key is not null.
 * 
 * @param hash_out output variable for actual length of the hash (max 64 bytes)
 * @param hash_length desired hash length
 * @param message pointer to the message to be hashed 
 * @param length length of the message to be hashed
 * @param key key for keyed hashing - can be NULL for unkeyed hashes
 * @param key_length length of the key
 * @param iters number of iterations to run the hashing algorithm
 */
void cc_hash_internal(uint8_t *hash_out, size_t hash_length, const uint8_t *message, size_t length, const uint8_t *key, size_t key_length, size_t iters) {
    if (hash_length > 64) hash_length = 64;
    if (iters < 1) iters = 1;

    uint8_t hash_tmp[64];
    crypto_blake2b_ctx ctx;

    // Hash the initial message
    crypto_blake2b_init(&ctx);
    if (key) crypto_blake2b_update(&ctx, key, key_length);
    crypto_blake2b_update(&ctx, message, length);
    if (key) crypto_blake2b_update(&ctx, key, key_length);
    crypto_blake2b_final(&ctx, hash_tmp);

    if (iters > 1) {
        for (size_t i = 0; i < iters-1; i++) {
            crypto_blake2b_init(&ctx);
            crypto_blake2b_update(&ctx, hash_tmp, 64);
            crypto_blake2b_final(&ctx, hash_tmp);
        }
    }

    memcpy(hash_out, hash_tmp, hash_length);
    UTIL_ASSERT(memcmp(hash_out, hash_tmp, hash_length) == 0);
    crypto_wipe(hash_tmp, sizeof(hash_tmp));
}

/**
 * @brief Standard hash
 *
 * @param hash_out CC_HASH_LENGTH bytes
 * @param message message to be hashed
 * @param length length of the message
 */
void cc_hash(uint8_t *hash_out, const uint8_t *message, size_t length) {
    cc_hash_internal(hash_out, CC_HASH_LEN, message, length, NULL, 0, CC_HASH_ITERS);
}

/**
 * @brief Keyed hash
 * 
 * Expects CC_HASH_KEY_LEN byte-long key
 * 
 * @param hash_out CC_HASH_LENGTH bytes
 * @param message 
 * @param length 
 * @param key 
 */
void cc_hash_keyed(uint8_t *hash_out, const uint8_t *message, size_t length, const uint8_t *key) {
    cc_hash_internal(hash_out, CC_HASH_LEN, message, length, key, CC_HASH_KEY_LEN, CC_HASH_ITERS);
}

/**
 * @brief Key derivation function helper
 * 
 * @param hash_out CC_HASH_LENGTH bytes
 * @param pin attestation pin
 */
void _cc_kdf_internal(uint8_t *hash_out, const uint8_t *pw, size_t pw_len) {
    // Pull out 12 bytes of key material from the deployment key
    uint8_t hash_tmp[CC_HASH_LEN];
    cc_hash_internal(hash_tmp, CC_HASH_LEN, DEPLOYMENT_KEY, 12, NULL, 0, 4);

    // Do an iterated hash
    for (int i = 0; i < CC_KDF_PIN_ITERS; i++) {
        cc_hash_internal(hash_tmp, CC_HASH_LEN, hash_tmp, CC_HASH_LEN, pw, pw_len, 4);
        xor_bytes(hash_tmp, pw, pw_len);
    }
    
    // After the final hash, XOR in the plaintext once more to
    // guarantee a minimum amount of entropy in the key
    cc_hash(hash_tmp, hash_tmp, CC_HASH_LEN);
    xor_bytes(hash_tmp, pw, pw_len);

    SECURE_MEMCPY(hash_out, hash_tmp, CC_HASH_LEN);
    crypto_wipe(hash_tmp, sizeof(hash_tmp));
}

/**
 * @brief Key derivation function for using with attestation pin
 * 
 * @param hash_out CC_HASH_LENGTH bytes
 * @param pin attestation pin
 */
void cc_kdf_pin(uint8_t *hash_out, const uint8_t *pin) {
    _cc_kdf_internal(hash_out, pin, CC_PIN_LENGTH);
}

/**
 * @brief Key derivation function for using with replacement token
 * 
 * @param hash_out CC_HASH_LENGTH
 * @param replacement_token replacement token
 */
void cc_kdf_rt(uint8_t *hash_out, const uint8_t *replacement_token) {
    _cc_kdf_internal(hash_out, replacement_token, CC_RT_LENGTH);
}

/**
 * @brief Helper hash function to derive subkeys
 * 
 * @param hash_out output buffer for the hash
 * @param root_key root key to derive from 
 * @param comp_id component it
 * @param pepper salt and pepper to add to the hash
 * @param pepper_len length of pepper
 */
void _cc_kdf_subkey_internal(uint8_t *hash_out, const uint8_t *root_key, uint32_t comp_id, const char *pepper, size_t pepper_len) {
    uint8_t hash_tmp[CC_HASH_LEN];
    cc_hash_internal(hash_tmp, CC_HASH_LEN, root_key, CC_ROOTKEY_LENGTH, (const uint8_t*)pepper, pepper_len, 4);

    uint8_t id_hash[CC_HASH_LEN];
    cc_hash_internal(id_hash, CC_HASH_LEN, (const uint8_t*)&comp_id, sizeof(comp_id), NULL, 0, 4);

    // Do an iterated hash
    for (int i = 0; i < CC_KDF_SUBKEY_ITERS; i++) {
        cc_hash_internal(hash_tmp, CC_HASH_LEN, hash_tmp, CC_HASH_LEN, id_hash, CC_HASH_LEN, 4);
        xor_bytes(hash_tmp, (const uint8_t*)&comp_id, sizeof(comp_id));
    }
    
    // After the final hash, XOR in the plaintext once more to
    // guarantee a minimum amount of entropy in the key
    cc_hash(hash_tmp, hash_tmp, CC_HASH_LEN);
    xor_bytes(hash_tmp, root_key, CC_ROOTKEY_LENGTH);

    SECURE_MEMCPY(hash_out, hash_tmp, CC_HASH_LEN);
    crypto_wipe(hash_tmp, sizeof(hash_tmp));
    crypto_wipe(id_hash, sizeof(id_hash));
}

/**
 * @brief Key derivation function for using with AP boot root key to derive sub keys
 * 
 * @param hash_out CC_HASH_LENGTH bytes
 * @param ap_boot_root_key AP boot root key
 * @param comp_id component id
 */
void cc_kdf_ap_boot_sub_key(uint8_t *hash_out, const uint8_t *ap_boot_root_key, uint32_t comp_id) {
    _cc_kdf_subkey_internal(hash_out, ap_boot_root_key, comp_id, "apbootsubkey----", 16);
}

/**
 * @brief Key derivation function for using with comp boot root key to derive sub keys
 * 
 * @param hash_out CC_HASH_LENGTH bytes
 * @param comp_boot_root_key comp boot root key
 * @param comp_id component id
 */
void cc_kdf_comp_boot_sub_key(uint8_t *hash_out, const uint8_t *comp_boot_root_key, uint32_t comp_id) {
    _cc_kdf_subkey_internal(hash_out, comp_boot_root_key, comp_id, "compbootsubkey--", 16);
}

/**
 * @brief Key derivation function for using with attestation root key to derive sub keys
 * 
 * @param hash_out CC_HASH_LENGTH bytes
 * @param att_boot_root_key attestation root key
 * @param comp_id component id
 */
void cc_kdf_att_sub_key(uint8_t *hash_out, const uint8_t *att_root_key, uint32_t comp_id) {
    _cc_kdf_subkey_internal(hash_out, att_root_key, comp_id, "attestsubkey----", 16);
}

/**
 * @brief Key derivation function for using with secure send/receive root key to derive sub keys
 * 
 * @param hash_out CC_HASH_LENGTH bytes
 * @param sec_send_root_key secure send/receive root key
 * @param comp_id component id
 */
void cc_kdf_sec_send_sub_key(uint8_t *hash_out, const uint8_t *sec_send_root_key, uint32_t comp_id) {
    _cc_kdf_subkey_internal(hash_out, sec_send_root_key, comp_id, "secsendsubkey---", 16);
}

/**
 * @brief Given byte arrays A and B, XORs the first len(B) bytes of A with B, and retains the rest of A as-is.
 * 
 * @param buf_out buffer A
 * @param buf2 buffer B
 * @param length length of buffer B
 */
void xor_bytes(uint8_t *buf_out, const uint8_t *buf2, size_t length) {
    for (size_t i = 0; i < length; i++) {
        buf_out[i] = buf_out[i] ^ buf2[i];
    }
}

