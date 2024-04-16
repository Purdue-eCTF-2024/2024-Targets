/**
 * @file "hmac_compare.c"
 * @author Kevin Marquis
 * @brief Simple, secure comparison tool implemntation.
 * @date 2024
*/

#include "hmac_compare.h"

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Compares two buffers of data using a double hmac protocol.
 *
 * @param known A pointer to a buffer of length known_size containing the
 *          known secret to compare against.
 * @param guess A pointer to a buffer of length guess_size containing the
 *          guess to compare with the known value (known).
 * @param known_size The size (in bytes) of the known buffer.
 * @param guess_size The size (in bytes) of the guess buffer.
 *
 * @return 0 if known and guess are equal.  Other values if unequal.
 */
int double_hmac_cmp(uint8_t * known, uint8_t * guess, int known_size, int guess_size){
    int ret;
    Hmac guess_mac, known_mac;
    uint8_t key[HMAC_KEY_SIZE];
    uint8_t guess_hash[HASH_OUTPUT_SIZE], known_hash[HASH_OUTPUT_SIZE];

    #if DEBUG
    print_debug("Comparing two buffers with HMAC\n");
    #endif


    MXC_TRNG_Random(key, HMAC_KEY_SIZE); //Use TRNG to generate a random key
    #if DEBUG
    print_debug("Computed random key...\n");
    #endif

    //Set up and compute HMAC for the guess
    ret = wc_HmacSetKey(&guess_mac, WC_SHA256, key, HMAC_KEY_SIZE);
    if (ret != 0){
        print_error("Failed to set up Guess HMAC. Error code: %d\n", ret);
        return -1;
    }

    ret = wc_HmacUpdate(&guess_mac, guess, guess_size);
    if (ret != 0){
        print_error("Failed to add guess to HMAC context.  Error: %d\n", ret);
        return -2;
    }

    ret = wc_HmacFinal(&guess_mac, guess_hash);
    if (ret != 0){
        print_error("Failed to compute guess HMAC!  Error: %d\n", ret);
        return -3;
    }

    //Set up and compute HMAC for the known value
    ret = wc_HmacSetKey(&known_mac, WC_SHA256, key, HMAC_KEY_SIZE);
    if (ret != 0){
        print_error("Failed to set up Known HMAC. Error code: %d\n", ret);
        return -4;
    }

    ret = wc_HmacUpdate(&known_mac, known, known_size);
    if (ret != 0){
        print_error("Failed to add known value to HMAC context.  Error: %d\n", ret);
        return -5;
    }

    ret = wc_HmacFinal(&known_mac, known_hash);
    if (ret != 0){
        print_error("Failed to compute known HMAC!  Error: %d\n", ret);
        return -6;
    }

    //HMACs are computed...now compare the hashes:
    ret = memcmp(guess_hash, known_hash, HASH_OUTPUT_SIZE);
    #if DEBUG
    if (ret == 0){
        print_debug("Strings are equal!\n");
    }
    else{
        print_debug("Strings are different!\n");
    }
    #endif

    return ret;
}
