#ifndef HELPER_FUNCTIONS_H
#define HELPER_FUNCTIONS_H
// include <stdlib.h>
#include <stdint.h>

#define CONCAT(a, b) a##b
#define UNIQUE_NAME() CONCAT("temp_", __COUNTER__)

/**
 * Datatype for commands sent to components.
 */
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST,
} component_cmd_t;
/**
 * Represents a scan-component message.
 */
typedef struct {
    uint32_t component_id;
} scan_message;
/**
 * Panic and reset, starting a panic timer.
 *
 * @param msg Message to write to stdout.
 */
void panic();
/**
 * @brief Initialize the built-in TRNG.
 *
 * Call the functions to enable the in-built TRNG of the microcontroller. This
 * is REQUIRED for secure cryptography.
 */
void init_rng();
/**
 * Generate a random 32-bit integer from the TRNG.
 */
uint32_t rand_uint();
/**
 * Waste a random amount of time.
 */
void spin();
/**
 * Enable the internal primary oscillator as the clock source.
 */
void switch_internal_clock();
/**
 * Ensure that a string does not have format strings.
 *
 * @param str Sting to check
 * @param len Length of string
 */
uint8_t verify_string(const char *str, uint32_t len);
/**
 * Disable the RISC-V co-processor.
 */
void disable_extra();
#endif
