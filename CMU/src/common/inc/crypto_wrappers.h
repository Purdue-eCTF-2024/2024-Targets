/**
 * @file crypto_wrappers.h
 * @author Plaid Parliament of Pwning
 * @brief Crypto wrappers over monocypher for providing a simplified interface
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include "monocypher.h"

#define CC_PIN_LENGTH 6
#define CC_RT_LENGTH 16
#define CC_ROOTKEY_LENGTH 32

#define CC_NONCE_HASH_LEN 64
#define CC_NONCE_RAND_LEN 24

#define CC_HASH_ITERS 16
#define CC_HASH_LEN 32
#define CC_HASH_KEY_LEN 32

#define CC_ENC_SYM_KEY_LEN 32

#define CC_ENC_SYM_METADATA_LEN 40
#define CC_ENC_ASYM_METADATA_LEN 72

#define CC_KDF_PIN_ITERS 750
#define CC_KDF_RT_ITERS 750
#define CC_KDF_SUBKEY_ITERS 32

void cc_encrypt_symmetric(uint8_t *ciphertext, const uint8_t *plaintext, size_t length, const uint8_t *sym_key, const uint8_t *rand_buf);

int cc_decrypt_symmetric(uint8_t *plaintext, const uint8_t *ciphertext, size_t length, const uint8_t *sym_key);

void cc_hash_internal(uint8_t *hash_out, size_t hash_length, const uint8_t *message, size_t length, const uint8_t *key, size_t key_length, size_t iters);

void cc_hash(uint8_t *hash_out, const uint8_t *message, size_t length);

void cc_hash_keyed(uint8_t *hash_out, const uint8_t *message, size_t length, const uint8_t *key);

void cc_kdf_pin(uint8_t *hash_out, const uint8_t *pin);

void cc_kdf_rt(uint8_t *hash_out, const uint8_t *replacement_token);

void cc_kdf_ap_boot_sub_key(uint8_t *hash_out, const uint8_t *ap_boot_root_key, uint32_t comp_id);

void cc_kdf_comp_boot_sub_key(uint8_t *hash_out, const uint8_t *comp_boot_root_key, uint32_t comp_id);

void cc_kdf_att_sub_key(uint8_t *hash_out, const uint8_t *att_root_key, uint32_t comp_id);

void cc_kdf_sec_send_sub_key(uint8_t *hash_out, const uint8_t *sec_send_root_key, uint32_t comp_id);

void xor_bytes(uint8_t *buf_out, const uint8_t *buf2, size_t length);
