#include "secure_component.h"
#include "boardlink_component.h"
#include "crypto_wolfssl.h"
#include "helper_functions.h"
#include "secure_buffer.h"
#include "stdio.h"
#include <string.h>

int component_auth(uint32_t self_id, buf_u8 msg_buf, buf_u8 key_buf,
                   crypto_config *out_c) {
    assert_min_size_bu8(key_buf, MASTER_KEY_COUNT * KEY_LEN_BYTES);
    out_c->component_id = self_id;

    INIT_BUF_U8(cmp_id_buf, 4);
    cpyin_raw_bu8(cmp_id_buf, (uint8_t*)&self_id, 4);

    // messages passed:
    // ap --> comp: "AUTH" key_i nonce1
    // comp --> ap: nonce2 h2=hmac(nonce1||nonce2)
    // ap --> comp: hmac(h2)

    // verify that it's an auth request
    assert_size_exact_bu8(msg_buf, 40);
    char *auth = "AUTH";
    if (strncmp(auth, (char *)msg_buf.data, 4) != 0) {
        panic();
    }
    buf_u8 r1_buf = slice_bu8(msg_buf, 8, 40);

    INIT_BUF_U8(challenge, 68);
    buf_u8 r2_buf = slice_bu8(challenge, 32, 64);
    rand_bytes(r2_buf);
    cpy_bu8(challenge, r1_buf, 32);
    cpy_bu8(slice_bu8(challenge, 64, 68), cmp_id_buf, 4);

    uint32_t key_i = *(uint32_t *)(msg_buf.data + 4);
    if (key_i >= MASTER_KEY_COUNT) {
        panic();
    }
    derived_key tmp;
    memcpy(
        tmp.key,
        slice_bu8(key_buf, key_i * KEY_LEN_BYTES, (key_i + 1) * KEY_LEN_BYTES)
            .data,
        32);
    tmp.round = 0;

    // send h2 = hmac(nonce1||nonce2||component_id)
    INIT_BUF_U8(h2_buf, 32);
    hmac(challenge, &tmp, h2_buf);
    concat_bu8(r2_buf, h2_buf, challenge);
    int res = send_packet_and_ack(slice_bu8(challenge, 0, 64));
    if (res != SUCCESS_RETURN)
        return res;

    // receive h3 = hmac(h2)
    int rec_size = wait_and_receive_packet(msg_buf);
    spin();
    if (rec_size != 32) {
        panic();
    }
    INIT_BUF_U8(h3_buf, 32);
    hmac(h2_buf, &tmp, h3_buf);
    spin();
    if (!cmp_bu8(h3_buf, slice_bu8(msg_buf, 0, 32))) {
        panic();
    }

    for (int i = 0; i < MASTER_KEY_COUNT; i++) {
        out_c->keys[i] = initialize_derived_key(
            slice_bu8(key_buf, i * KEY_LEN_BYTES, (i + 1) * KEY_LEN_BYTES),
            h2_buf);
    }
    return SUCCESS_RETURN;
}

int component_send(buf_u8 buf, crypto_config *c) {
    uint32_t key_i = rand_uint() % MASTER_KEY_COUNT;

    INIT_BUF_U8(plaintext_buf, buf.size + 64);
    INIT_BUF_U8(msg_buf, buf.size + 100);

    // sent message structure: <key num><key round><hmac><encrypted buf>
    // encrypted buf has <component-id> at the start on decryption

    INIT_BUF_U8(int_buf, 4);
    memcpy(int_buf.data, &(c->component_id), 4);

    derived_key *k = &c->keys[key_i];
    uint32_t bytes = concat_bu8(int_buf, buf, plaintext_buf);
    spin();
    bytes = encrypt_buf(slice_bu8(plaintext_buf, 0, bytes), k, msg_buf);

    INIT_BUF_U8(hmac_buf, 32);
    hmac(slice_bu8(msg_buf, 0, bytes), k, hmac_buf);

    bytes = concat_bu8(hmac_buf, slice_bu8(msg_buf, 0, bytes), msg_buf);
    memcpy(int_buf.data, &k->round, 4);
    bytes = concat_bu8(int_buf, slice_bu8(msg_buf, 0, bytes), msg_buf);
    memcpy(int_buf.data, &key_i, 4);
    bytes = concat_bu8(int_buf, slice_bu8(msg_buf, 0, bytes), msg_buf);

    advance_key(k, k->round + 1);

    return send_packet_and_ack(slice_bu8(msg_buf, 0, bytes));
}

int component_receive(buf_u8 buf_in, crypto_config *c) {
    int rec_bytes = buf_in.size;
    // need to have key_i, round, hmac, data
    if (rec_bytes < 56) {
        return ERROR_RETURN;
    }

    uint32_t key_i = *(uint32_t *)buf_in.data;
    uint32_t round = *(uint32_t *)(buf_in.data + 4);
    derived_key *k = &c->keys[key_i];
    if (!advance_key(k, round)) {
        panic();
    }

    buf_u8 hmac_slice = slice_bu8(buf_in, 8, 40);
    buf_u8 enc_slice = slice_bu8(buf_in, 40, rec_bytes);

    INIT_BUF_U8(hmac_buf, 32);
    hmac(enc_slice, k, hmac_buf);
    spin();
    if (!cmp_bu8(hmac_slice, hmac_buf)) {
        panic();
    }

    INIT_BUF_U8(msg_buf, rec_bytes);
    uint32_t dec_bytes = (uint32_t)decrypt_buf(enc_slice, k, msg_buf);

    if (*(uint32_t*)msg_buf.data != c->component_id) {
        panic();
    }

    cpy_bu8(buf_in, slice_bu8(msg_buf, 4, dec_bytes), dec_bytes - 4);
    spin();
    advance_key(k, k->round + 1);
    return dec_bytes - 4;
}
