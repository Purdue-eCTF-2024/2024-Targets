/**
 * @file "common_crypto.h"
 * @brief Common crypto structs
 */

#ifndef _COMMON_CRYPTO_H_
#define _COMMON_CRYPTO_H_

#include "global_secrets.h"
#include "common_msg.h"
#include "simple_trng.h"

#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hash.h>

#define MIT_HASH_SIZE SHA256_DIGEST_SIZE

typedef struct __attribute__((packed)) {
    uint8_t rawBytes[MIT_HASH_SIZE];
} mit_hash_t;

#define mit_ConstantCompare_nonce(a, b) mit_ConstantCompare(a, b, sizeof(mit_nonce_t))
#define mit_ConstantCompare_hash(a,b) mit_ConstantCompare(a, b, sizeof(mit_hash_t))
#define mit_ConstantCompare_challenge(a,b) mit_ConstantCompare(a, b, sizeof(mit_challenge_t))

int mit_ConstantCompare(const uint8_t* a, const uint8_t* b, int length);

void get_random_challenge(mit_challenge_t * challenge);

int mit_sha256(const uint8_t * input, uint8_t len, mit_hash_t * hash);

int mit_encrypt(mit_packet_t * packet, uint8_t * plaintext, uint8_t len);
int mit_decrypt(mit_packet_t * packet, uint8_t * plaintext);

#endif