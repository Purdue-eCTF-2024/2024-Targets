#ifndef SECURE_AP_H
#define SECURE_AP_H

#include "crypto_wolfssl.h"
#include "global_secrets.h"

// Set of derived ratcheting keys used by the AP
typedef struct crypto_config {
    uint32_t component_id;
    derived_key keys[MASTER_KEY_COUNT];
} crypto_config;

// Authenticate a component with a given ID through i2c, and intializes the
// derived keys to be used for the communication. Returns `false` on failure.
int ap_auth(uint32_t component_id, const buf_u8 key_buf, crypto_config *out_c);

// Encrypt and send an authenticated buffer over i2c to a specified component,
// advancing derived keys. Returns `false` on failure.
int ap_send(const buf_u8 buf, crypto_config *c);

// Receive, validate and decrypt a message from a given component by polling it,
// matching derived keys to the round received. Returns the number of bytes
// written to buf_out.
int ap_receive(buf_u8 buf_out, crypto_config *c);

#endif
