/**
 * @file "hmac_compare.h"
 * @author Kevin Marquis
 * @brief Simple, secure comparison tool header.
 * @date 2024
*/

#include "wolfssl/wolfcrypt/hmac.h"
#include "simple_trng.h"
#include "trng.h"
#include "host_messaging.h"
#include <stdint.h>
#include <string.h>

#define HMAC_KEY_SIZE 32
#define HASH_OUTPUT_SIZE 32

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
int double_hmac_cmp(uint8_t * known, uint8_t * guess, int known_size, int guess_size);
