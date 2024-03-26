/**
 * @file "common_crypto.c"
 * @author MIT TechSec
 * @brief Common crypto needs
 * @date 2024
 */

#include "common_crypto.h"

// Borrowed from wolfSSL library
// Just couldn't easily compile it in :)
int mit_ConstantCompare(const uint8_t* a, const uint8_t* b, int length) {
    int i;
    int compareSum = 0;

    for (i = 0; i < length; i++) {
        compareSum |= a[i] ^ b[i];
    }

    return compareSum;
}

void get_random_challenge(mit_challenge_t * challenge) {
    get_rand_bytes(challenge->rawBytes, MIT_CHALLENGE_SIZE);
}

int mit_sha256(const uint8_t * input, uint8_t len, mit_hash_t * hash) {
    int ret = wc_Sha256Hash(input, len, hash);
    if (ret != 0) {
        memset(hash, 0, MIT_HASH_SIZE);
        return ret;
    }

    return ret;
}

int mit_encrypt(mit_packet_t * packet, uint8_t * plaintext, uint8_t len) {

    const uint8_t * iv    = packet->ad.nonce.rawBytes;
    const uint8_t * inAAD = &packet->ad;
    uint8_t * ciphertext  = packet->message.rawBytes;
    uint8_t * authTag     = packet->authTag.rawBytes;

    if ((mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, null_nonce) == 0)) {
        return -1;
    }

    return wc_ChaCha20Poly1305_Encrypt(
        SHARED_SECRET_KEY, iv, // key, iv
        inAAD, sizeof(mit_ad_t),  // ad, len(ad)
        plaintext, len,        // plaintext, len(plaintext),
        ciphertext, authTag    // ciphertext, authTag
    );
}

int mit_decrypt(mit_packet_t * packet, uint8_t * plaintext) {

    const uint8_t * iv    = packet->ad.nonce.rawBytes;
    const uint8_t * inAAD = &packet->ad;
    const uint8_t * ciphertext  = packet->message.rawBytes;
    const uint8_t * authTag     = packet->authTag.rawBytes;
    const uint8_t len           = packet->ad.len;

    if ((mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, null_nonce) == 0) ||
        (mit_ConstantCompare_nonce(packet->ad.nonce.rawBytes, null_nonce) == 0)) {
        return -1;
    }

    return wc_ChaCha20Poly1305_Decrypt(
        SHARED_SECRET_KEY, iv,
        inAAD, sizeof(mit_ad_t),
        ciphertext, len,
        authTag, plaintext
    );
}
