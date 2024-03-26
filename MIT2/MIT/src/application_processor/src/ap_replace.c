/**
 * @file ap_replace.c
 * @author MIT TechSec
 * @brief Replace-related functions for AP
 * @date 2024
 */

#include "ap_common.h"

// SALT_LEN + TOKEN_LEN = 48
#define SALT_LEN MIT_HASH_SIZE
#define TOKEN_LEN 16
static uint8_t guess_buf[SALT_LEN + TOKEN_LEN] = REPLACE_SALT;
static uint8_t guessed_hash[MIT_HASH_SIZE] = {0};

static int compare_token(char * token);
static int swap_components(mit_comp_id_t component_id_in, mit_comp_id_t component_id_out);

// Replace a component if the PIN is correct
int attempt_replace() {
    delay_rnd;

    char * buf = get_uart_buf();
    recv_input("Enter token: ", TOKEN_LEN);

    delay_rnd;

    // REDUNDANT
    if (compare_token(buf) || compare_token(buf) || compare_token(buf)) {
        delay_4s;
        print_error("Invalid Token!\n");
        return ERROR_RETURN;
    }

    delay_1s;
    print_debug("Token Accepted!\n");

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", 10);  // 0x + 8 chars
    component_id_in = (uint32_t)strtoul(buf, buf + 10, 16);
    recv_input("Component ID Out: ", 10); // 0x + 8 chars
    component_id_out = (uint32_t)strtoul(buf, buf + 10, 16);

    delay_rnd;

    if (swap_components(component_id_in, component_id_out) == ERROR_RETURN) {
        print_error("Cannot replace component 0x%08x with component 0x%08x\n",
            component_id_out, component_id_in);
        return ERROR_RETURN;
    }

    print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
            component_id_in);
    print_success("Replace\n");
}

int compare_token(char * token) {
    delay_rnd;

    int ret;

    // Copy guess into end of buffer
    // REDUNDANT
    memcpy(&guess_buf[MIT_HASH_SIZE], token, TOKEN_LEN);
    memcpy(&guess_buf[MIT_HASH_SIZE], token, TOKEN_LEN);
    memcpy(&guess_buf[MIT_HASH_SIZE], token, TOKEN_LEN);

    delay_rnd;

    // Fill guessed_hash with garbage
    // REDUNDANT
    get_rand_bytes(guessed_hash, MIT_HASH_SIZE);
    get_rand_bytes(guessed_hash, MIT_HASH_SIZE);
    get_rand_bytes(guessed_hash, MIT_HASH_SIZE);

    delay_rnd;

    // Compute hash over salt + guess
    ret = mit_sha256(guess_buf, SALT_LEN + TOKEN_LEN, guessed_hash);
    if (ret != 0) {
        return ERROR_RETURN;
    }

    uint8_t * hashed_token = getHashedTokenPtr();

    delay_rnd;

    // Compare with precomputed salt+actual_token
    // REDUNDANT
    if (mit_ConstantCompare_hash(guessed_hash, hashed_token) ||
        mit_ConstantCompare_hash(guessed_hash, hashed_token) ||
        mit_ConstantCompare_hash(guessed_hash, hashed_token)) {
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}

// Swap component IN with component OUT
int __attribute__((optimize("O0"))) swap_components(mit_comp_id_t component_id_in, mit_comp_id_t component_id_out) {
    delay_rnd;

    flash_entry * flash_status = get_flash_status();
    i2c_addr_t addr = component_id_to_i2c_addr(component_id_in);

    // Check against denylist
    if ((addr <  0x8)  ||
        (addr >= 0x78) ||
        (addr == 0x18 || addr == 0x28 || addr == 0x36)) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Ensure that component_id_in is not already provisioned
    // REDUNDANT
    for (unsigned i = 0; i < COMPONENT_CNT; i++) {
        delay_rnd;

        if ((flash_status->component_ids[i] == component_id_in) ||
            (flash_status->component_ids[i] == component_id_in) ||
            (flash_status->component_ids[i] == component_id_in)) {
            return ERROR_RETURN;
        }
    }

    // Let's just check again :-)
    for (unsigned i = 0; i < COMPONENT_CNT; i++) {
        delay_rnd;

        if ((flash_status->component_ids[i] == component_id_in) ||
            (flash_status->component_ids[i] == component_id_in) ||
            (flash_status->component_ids[i] == component_id_in)) {
            return ERROR_RETURN;
        }
    }

    // Find the component to swap out
    for (unsigned i = 0; i < COMPONENT_CNT; i++) {
        delay_rnd;

        if (flash_status->component_ids[i] == component_id_out) {
            // Grab outgoing session
            mit_session_t * session = get_session_of_component(component_id_out);
            if (session == NULL) {
                return ERROR_RETURN;
            }

            delay_rnd;

            // Swap out component id
            flash_status->component_ids[i] = component_id_in;

            // Reset session info
            // REDUNDANT
            memset(session->rawBytes, 0, sizeof(mit_session_t));
            memset(session->rawBytes, 0, sizeof(mit_session_t));
            memset(session->rawBytes, 0, sizeof(mit_session_t));

            delay_rnd;

            session->component_id = component_id_in;

            // REDUNDANT
            get_rand_bytes(session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
            get_rand_bytes(session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));
            get_rand_bytes(session->outgoing_nonce.rawBytes, sizeof(mit_nonce_t));

            delay_rnd;

            // REDUNDANT
            memset(session->incoming_nonce.rawBytes, 0, sizeof(mit_nonce_t));
            memset(session->incoming_nonce.rawBytes, 0, sizeof(mit_nonce_t));
            memset(session->incoming_nonce.rawBytes, 0, sizeof(mit_nonce_t));

            delay_rnd;

            // write updated component_ids to flash
            rewrite_flash_entry();

            return SUCCESS_RETURN;
        }
    }

    return ERROR_RETURN;
}
