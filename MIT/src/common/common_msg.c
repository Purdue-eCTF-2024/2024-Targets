/**
 * @file "common_msg.c"
 * @author MIT TechSec
 * @brief Common messaging needs
 * @date 2024
 */

#include "common_msg.h"
#include "common_crypto.h"

uint8_t null_nonce[MIT_NONCE_SIZE] = {0};

void increment_nonce(mit_nonce_t * nonce, mit_nonce_t * old_nonce) {
    if (mit_ConstantCompare_nonce(nonce->rawBytes, old_nonce->rawBytes) != 0) {
        return;
    }

    uint32_t * sections = (uint32_t *)nonce->rawBytes;
    bool carry = true;

    for (int i = sizeof(mit_nonce_t)/sizeof(uint32_t) - 1; i >= 0; i--) {
        if (carry) {
            carry = false;
            if (sections[i] == 0xffffffff) {
                carry = true;
            }
            sections[i]++;
        }
    }
}
