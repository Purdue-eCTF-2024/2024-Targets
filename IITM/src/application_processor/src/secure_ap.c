#include "secure_ap.h"
#include "crypto_wolfssl.h"
#include "helper_functions.h"
#include "secure_buffer.h"
#include "secure_host_messaging.h"
#include "simple_i2c_ap.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "boardlink_ap.h"

int ap_auth(uint32_t component_id, buf_u8 key_buf, crypto_config *out_c) {
    assert_min_size_bu8(key_buf, MASTER_KEY_COUNT * KEY_LEN_BYTES);
    out_c->component_id = component_id;

    INIT_BUF_U8(cmp_id_buf, 4);
    cpyin_raw_bu8(cmp_id_buf, (uint8_t*)&component_id, 4);

    // send out first message
    INIT_BUF_U8(send_buf, 40);
    char *header = "AUTH";
    uint32_t key_i = rand_uint() % MASTER_KEY_COUNT;
    memcpy(send_buf.data, header, 4);
    memcpy(send_buf.data + 4, &key_i, 4);
    buf_u8 r1_slice = slice_bu8(send_buf, 8, 40);
    rand_bytes(r1_slice);

    int res = send_packet_and_ack(component_id, send_buf);
    spin();
    if (res != SUCCESS_RETURN)
        return res;

    // receive message
    INIT_BUF_U8(recv_buf, 64);
    int rec_size = poll_and_receive_packet(component_id, recv_buf);
    if (rec_size != 64) {
        panic();
    }
    buf_u8 r2_slice = slice_bu8(recv_buf, 0, 32);
    buf_u8 h2_slice = slice_bu8(recv_buf, 32, 64);

    // keep this ready for doing HMACs
    derived_key tmp;
    memcpy(
        tmp.key,
        slice_bu8(key_buf, key_i * KEY_LEN_BYTES, (key_i + 1) * KEY_LEN_BYTES)
            .data,
        32);
    tmp.round = 0;
    spin();
    // validate message
    INIT_BUF_U8(hmac_buf, 32);
    INIT_BUF_U8(challenge, 68);
    concat_bu8(r1_slice, r2_slice, challenge);
    cpy_bu8(slice_bu8(challenge, 64, 68), cmp_id_buf, 4);
    hmac(challenge, &tmp, hmac_buf);

    if (!cmp_bu8(h2_slice, hmac_buf)) {
        panic();
    }

    // send h3

    hmac(hmac_buf, &tmp, hmac_buf);
    res = send_packet_and_ack(component_id, hmac_buf);
    spin();
    if (res != SUCCESS_RETURN)
        return res;
    // derive keys with h2 as nonce
    for (int i = 0; i < MASTER_KEY_COUNT; i++) {
        out_c->keys[i] = initialize_derived_key(
            slice_bu8(key_buf, i * KEY_LEN_BYTES, (i + 1) * KEY_LEN_BYTES),
            h2_slice);
    }
    return SUCCESS_RETURN;
}

int ap_send(buf_u8 buf, crypto_config *c) {
    uint32_t key_i = rand_uint() % MASTER_KEY_COUNT;
    INIT_BUF_U8(int_buf, 4);
    INIT_BUF_U8(msg_plus_id_buf, buf.size + 4);
    INIT_BUF_U8(msg_buf, msg_plus_id_buf.size + 128);

    cpyin_raw_bu8(int_buf, (uint8_t*)&c->component_id, 4);
    concat_bu8(int_buf, buf, msg_plus_id_buf);
    derived_key *k = &c->keys[key_i];
    int bytes = encrypt_buf(msg_plus_id_buf, k, msg_buf);

    INIT_BUF_U8(hmac_buf, 32);
    hmac(slice_bu8(msg_buf, 0, bytes), k, hmac_buf);
    bytes = concat_bu8(hmac_buf, slice_bu8(msg_buf, 0, bytes), msg_buf);
    spin();
    memcpy(int_buf.data, &k->round, 4);
    bytes = concat_bu8(int_buf, slice_bu8(msg_buf, 0, bytes), msg_buf);
    memcpy(int_buf.data, &key_i, 4);
    bytes = concat_bu8(int_buf, slice_bu8(msg_buf, 0, bytes), msg_buf);

    advance_key(k, k->round + 1);
    spin();
    int res =
        send_packet_and_ack(c->component_id, slice_bu8(msg_buf, 0, bytes));
    if (res != SUCCESS_RETURN)
        return res;
    spin();
    return SUCCESS_RETURN;
}

int ap_receive(buf_u8 buf_out, crypto_config *c) {
    int rec_bytes = poll_and_receive_packet(c->component_id, buf_out);

    if (rec_bytes <= 0)
        return rec_bytes;

    // need to have key_i, round, hmac, data
    if (rec_bytes < 56) {
        panic();
        return ERROR_RETURN;
    }

    uint32_t key_i = *(uint32_t *)buf_out.data;
    if (key_i >= MASTER_KEY_COUNT) {
        panic();
        return ERROR_RETURN;
    }
    derived_key *k = &c->keys[key_i];
    uint32_t round = *(uint32_t *)(buf_out.data + 4);

    spin();
    if (!advance_key(k, round)) {
        panic();
    }

    // validate the received HMAC
    buf_u8 hmac_slice = slice_bu8(buf_out, 8, 40);
    buf_u8 encrypted_slice = slice_bu8(buf_out, 40, rec_bytes);
    INIT_BUF_U8(hmac_buf, 32);
    hmac(encrypted_slice, k, hmac_buf);
    if (!cmp_bu8(hmac_slice, hmac_buf)) {
        panic();
    }

    INIT_BUF_U8(msg_buf, rec_bytes);
    uint32_t dec_bytes = decrypt_buf(encrypted_slice, k, msg_buf);

    uint32_t recv_id = *(uint32_t *)msg_buf.data;
    if (recv_id != c->component_id) {
        panic();
    }

    cpy_bu8(buf_out, slice_bu8(msg_buf, 4, dec_bytes), dec_bytes - 4);
    advance_key(k, k->round + 1);
    return dec_bytes - 4;
}
