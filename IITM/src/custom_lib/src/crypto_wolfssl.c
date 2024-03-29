#include "crypto_wolfssl.h"
#include "helper_functions.h"
#include "secure_buffer.h"
#include "secure_host_messaging.h"
#include "string.h"
#include "trng.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/sha3.h"

void rand_bytes(buf_u8 buf) {
    MXC_TRNG_Random(buf.data, buf.size);
}

derived_key initialize_derived_key(buf_u8 master_key, buf_u8 nonce) {
    assert_size_exact_bu8(master_key, KEY_LEN_BYTES);
    derived_key k;
    memcpy(k.key, master_key.data, KEY_LEN_BYTES);
    for (int i = 0; i < KEY_LEN_BYTES; i++) {
        k.key[i] ^= access_u8(nonce, i % nonce.size);
    }
    k.round = 0;
    advance_key(&k, 1);
    return k;
}

bool advance_key(derived_key *k, uint32_t round) {
    if (round < k->round || round - k->round > MAX_KEY_ADVANCE_ROUNDS) {
        return false;
    }
    spin();
    while (k->round < round) {
        Hmac h;
        wc_HmacSetKey(&h, WC_SHA3_256, k->key, KEY_LEN_BYTES);
        wc_HmacUpdate(&h, (uint8_t *)(&k->round), 4);
        wc_HmacUpdate(&h, (uint8_t *)(&k->round), 4);
        wc_HmacUpdate(&h, (uint8_t *)(&k->round), 4);
        wc_HmacUpdate(&h, (uint8_t *)(&k->round), 4);
        wc_HmacUpdate(&h, (uint8_t *)(&k->round), 4);
        wc_HmacUpdate(&h, (uint8_t *)(&k->round), 4);
        wc_HmacUpdate(&h, (uint8_t *)(&k->round), 4);
        wc_HmacUpdate(&h, (uint8_t *)(&k->round), 4);
        wc_HmacFinal(&h, k->key);
        k->round++;
    }
    return true;
}

uint32_t encrypt_buf(const buf_u8 buf, const derived_key *key, buf_u8 buf_out) {
    // pads buf to make it divisible by block size
    int n = buf.size;
    int size = ((n + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    assert_min_size_bu8(buf_out, size + AES_BLOCK_SIZE);
    uint8_t pad = size - n;
    INIT_BUF_U8(buf_in, size);
    cpy_bu8(buf_in, buf, n);
    for (int i = n; i < size; i++) {
        set_u8(buf_in, i, pad);
    }
    Aes a;
    INIT_BUF_U8(iv, AES_BLOCK_SIZE);
    rand_bytes(iv);
    wc_AesSetKey(&a, key->key, KEY_LEN_BYTES, iv.data, AES_ENCRYPTION);
    if (wc_AesCbcEncrypt(&a, buf_out.data, buf_in.data, size) != 0) {
        panic();
        return 0;
    }
    concat_bu8(iv, slice_bu8(buf_out, 0, size), buf_out);
    return size + AES_BLOCK_SIZE;
}

uint32_t decrypt_buf(const buf_u8 buf, const derived_key *key, buf_u8 buf_out) {
    int size = buf.size - AES_BLOCK_SIZE;
    assert_min_size_bu8(buf_out, size);
    Aes a;
    wc_AesSetKey(&a, key->key, KEY_LEN_BYTES, buf.data, AES_DECRYPTION);
    spin();
    if (wc_AesCbcDecrypt(&a, buf_out.data,
                         slice_bu8(buf, AES_BLOCK_SIZE, buf.size).data,
                         size) != 0) {
        panic();
    }
    return size - buf_out.data[size - 1];
}

uint32_t hmac(const buf_u8 buf, const derived_key *key, buf_u8 buf_out) {
    assert_min_size_bu8(buf_out, 32);
    Hmac h;
    spin();
    wc_HmacSetKey(&h, WC_SHA3_256, key->key, KEY_LEN_BYTES);
    wc_HmacUpdate(&h, buf.data, buf.size);
    wc_HmacFinal(&h, buf_out.data);
    return 32;
}
