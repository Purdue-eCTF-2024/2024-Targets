#ifndef SECURE_COMPONENT_H
#define SECURE_COMPONENT_H

#include "crypto_wolfssl.h"
#include "global_secrets.h"

// Set of derived ratcheting keys, and the component ID, used by a component
typedef struct crypto_config {
    uint32_t component_id;
    derived_key keys[MASTER_KEY_COUNT];
} crypto_config;

// Wait and authenticate a component over I2C, with our own component ID.
// Returns `false` on failure.
int component_auth(uint32_t component_id, const buf_u8 msg_buf, const buf_u8 key_buf, crypto_config *out_c);

// Encrypt and prepare an authenticated message to be sent to the AP when
// polled, advancing derived keys. Returns `false` on failure.
int component_send(const buf_u8 buf, crypto_config *c);

// Receive, validate and decrypt a message from the AP, matching derived keys
// to the round received. Returns the number of bytes written to buf_out.
int component_receive(buf_u8 buf_in, crypto_config *c);

#endif
