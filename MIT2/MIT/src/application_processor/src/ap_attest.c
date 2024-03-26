/**
 * @file ap_attest.c
 * @author MIT TechSec
 * @brief Attest-related functions for AP
 * @date 2024
 */

#include "ap_common.h"

// SALT_LEN + PIN_LEN = 40
#define SALT_LEN MIT_HASH_SIZE
#define PIN_LEN 6
static uint8_t guess_buf[SALT_LEN + PIN_LEN] = ATTEST_SALT;
static uint8_t guessed_hash[MIT_HASH_SIZE] = {0};

static char pin_buf[6] = {0};

static int compare_pin(char * pin);

// Attest a component if the PIN is correct
int attempt_attest() {
    char * buf = get_uart_buf();
    recv_input("Enter pin: ", PIN_LEN);

    delay_rnd;

    // REDUNDANT
    memcpy(pin_buf, buf, PIN_LEN);
    memcpy(pin_buf, buf, PIN_LEN);
    memcpy(pin_buf, buf, PIN_LEN);

    delay_rnd;

    bool timeout = get_attest_timeout();

    // If we've guessed wrong before, add delay to prevent brute-force.
    if (timeout) {
        delay_4s;
    }

    // REDUNDANT
    if (compare_pin(pin_buf) || compare_pin(pin_buf) || compare_pin(pin_buf)) {
        if (!timeout) {
            set_attest_timeout();
        }
        print_error("Invalid PIN!\n");
        return ERROR_RETURN;
    }

    delay_1s;
    print_debug("Pin Accepted!\n");

    // Reset timeout status
    if (timeout) {
        unset_attest_timeout();
    }

    uint32_t component_id;
    recv_input("Component ID: ", 10); // 0x + 8 chars
    component_id = (uint32_t)strtoul(buf, buf + 10, 16);

    // Why not check again? :-)
    // REDUNDANT
    if (compare_pin(pin_buf) || compare_pin(pin_buf) || compare_pin(pin_buf)) {
        delay_4s;
        print_error("Invalid PIN!\n");
        return ERROR_RETURN;
    }

    delay_rnd;

    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
        return SUCCESS_RETURN;
    }

    print_error("Attestation failed\n");
    return ERROR_RETURN;
}

// Send attestation request to specific component
int attest_component(uint32_t component_id) {
    int ret, len;
    mit_challenge_t r1;

    delay_rnd;

    // Step 1: generate random challenge r1
    // REDUNDANT
    get_random_challenge(&r1);
    get_random_challenge(&r1);
    get_random_challenge(&r1);

    delay_rnd;

    // Step 2: construct AttestReq message
    mit_message_attestreq_t attestReq = {0};
    // REDUNDANT
    memcpy(attestReq.r1.rawBytes, r1.rawBytes, sizeof(mit_challenge_t));
    memcpy(attestReq.r1.rawBytes, r1.rawBytes, sizeof(mit_challenge_t));
    memcpy(attestReq.r1.rawBytes, r1.rawBytes, sizeof(mit_challenge_t));

    delay_rnd;

    ret = make_mit_packet(component_id, MIT_CMD_ATTESTREQ, attestReq.rawBytes, sizeof(mit_message_attestreq_t));
    if (ret != SUCCESS_RETURN) {
        return ret;
    }

    delay_rnd;

    // Step 3: send message
    len = issue_cmd(component_id, MIT_CMD_ATTESTREQ);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Step 4: Validate r1 is present in response
    mit_message_t * response = (mit_message_t *)ap_plaintext;
    // REDUNDANT
    if ((mit_ConstantCompare_challenge(response->attestReq.r1.rawBytes, attestReq.r1.rawBytes) != 0) ||
        (mit_ConstantCompare_challenge(response->attestReq.r1.rawBytes, attestReq.r1.rawBytes) != 0) ||
        (mit_ConstantCompare_challenge(response->attestReq.r1.rawBytes, attestReq.r1.rawBytes) != 0)) {
        return 
        ERROR_RETURN;
    }

    delay_rnd;

    // Step 4b: Check again for a valid pin, just for fun.
    // REDUNDANT
    if (compare_pin(pin_buf) || compare_pin(pin_buf) || compare_pin(pin_buf)) {
        print_error("Invalid PIN!\n");
        return ERROR_RETURN;
    }

    delay_rnd;

    // Step 5: Return r2
    mit_message_attest_t attest = {0};
    // REDUNDANT
    memcpy(attest.r2.rawBytes, response->attestReq.r2.rawBytes, sizeof(mit_challenge_t));
    memcpy(attest.r2.rawBytes, response->attestReq.r2.rawBytes, sizeof(mit_challenge_t));
    memcpy(attest.r2.rawBytes, response->attestReq.r2.rawBytes, sizeof(mit_challenge_t));

    delay_rnd;

    ret = make_mit_packet(component_id, MIT_CMD_ATTEST, attest.rawBytes, sizeof(mit_message_attest_t));
    if (ret != SUCCESS_RETURN) {
        return ret;
    }

    delay_rnd;

    // Step 6: send message
    len = issue_cmd(component_id, MIT_CMD_ATTEST);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    delay_rnd;

    // Step 7: Print attestation data
    response->rawBytes[sizeof(mit_message_t) - 1] = 0;
    print_info("C>0x%08x\n", component_id);
    print_info("%s", response->attest.customerData);
    return SUCCESS_RETURN;
}

static int compare_pin(char * pin) {
    int ret;

    delay_rnd;

    // Copy guess into end of buffer
    // REDUNDANT
    memcpy(&guess_buf[MIT_HASH_SIZE], pin, PIN_LEN);
    memcpy(&guess_buf[MIT_HASH_SIZE], pin, PIN_LEN);
    memcpy(&guess_buf[MIT_HASH_SIZE], pin, PIN_LEN);

    delay_rnd;

    // Fill guessed_hash with garbage
    // REDUNDANT
    get_rand_bytes(guessed_hash, MIT_HASH_SIZE);
    get_rand_bytes(guessed_hash, MIT_HASH_SIZE);
    get_rand_bytes(guessed_hash, MIT_HASH_SIZE);

    delay_rnd;

    // Compute hash over salt + guess
    ret = mit_sha256(guess_buf, SALT_LEN + PIN_LEN, guessed_hash);
    if (ret != 0) {
        return ERROR_RETURN;
    }

    delay_rnd;

    uint8_t * hashed_pin = getHashedPinPtr();

    // Compare with precomputed salt+actual_pin
    // REDUNDANT
    if (mit_ConstantCompare_hash(guessed_hash, hashed_pin) ||
        mit_ConstantCompare_hash(guessed_hash, hashed_pin) ||
        mit_ConstantCompare_hash(guessed_hash, hashed_pin)) {
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}
