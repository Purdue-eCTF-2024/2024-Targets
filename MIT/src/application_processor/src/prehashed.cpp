/**
 * @file prehashed.cpp
 * @author MIT TechSec
 * @brief Compile-time hashing of secrets
 * @date 2024
 */

#include "sha256_literal.h"
#include "global_secrets.h"
#include "ectf_params.h"

static constexpr sha256_literal::HashType hashed_pin   = sha256_literal::compute_str(ATTEST_SALT  AP_PIN);
static constexpr sha256_literal::HashType hashed_token = sha256_literal::compute_str(REPLACE_SALT AP_TOKEN);

const uint8_t * getHashedPinPtrCpp(void) {
    return (const uint8_t *)hashed_pin.data();
}

const uint8_t * getHashedTokenPtrCpp(void) {
    return (const uint8_t *)hashed_token.data();
}

#ifdef __cplusplus
extern "C" {
#endif

const uint8_t * getHashedPinPtr(void) {
    return getHashedPinPtrCpp();
}

const uint8_t * getHashedTokenPtr(void) {
    return getHashedTokenPtrCpp();
}

#ifdef __cplusplus
}
#endif