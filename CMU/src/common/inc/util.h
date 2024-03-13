/**
 * @file util.h
 * @author Plaid Parliament of Pwning
 * @brief Prototypes for common utitlity functions
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include "fiproc.h"  // For FIPROC_DELAY_WRAP

/**
 * @brief Called when hardware tampering is detected
 * 
 * Macro used when the system is detected to be in an unstable state
 * and cannot be recovered. This is only called when a hardware issue
 * or unreachable system state is detected, and should never be
 * possible to reach during normal operation.
 */
#define HALT_AND_CATCH_FIRE() FI_PROTECT_0; do_spin_forever(); FI_PROTECT_2;

/**
 * @brief Copy buffers with protection against fault injections
 * 
 * ASSERT: if the buffer doesn't match the copied data, something went horribly wrong (like a hardware fault)
 * Halt and catch fire if so.
 */
#define SECURE_MEMCPY(dst, src, len) do {        \
      memcpy(dst, src, len);                     \
      UTIL_ASSERT(memcmp(dst, src, len) == 0);   \
      FIPROC_DELAY_WRAP();                       \
      UTIL_ASSERT(memcmp(dst, src, len) == 0);   \
    } while (0)

/**
 * @brief Assert but with fault injection protections
 */
#define SEC_ASSERT(x) do {         \
     UTIL_ASSERT(x);               \
     FIPROC_DELAY_WRAP();          \
     UTIL_ASSERT(x);               \
    } while (0)


/**
 * @brief Assert and working if failed
 */
#define UTIL_ASSERT(x)             \
    do {                           \
        if (!(x)) {                \
            HALT_AND_CATCH_FIRE(); \
        }                          \
    } while (0)

#define SUCCESS_RETURN 0
#define ERROR_RETURN (-1)

/**
 * @brief Macros for fault injection prevention
 * 
 * Equivalent to a bunch of while(1);
 */
#define FI_PROTECT_0 __asm volatile( "1: ");  FI_PROTECT_1 FI_PROTECT_1
#define FI_PROTECT_1 FI_PROTECT_2 FI_PROTECT_2
#define FI_PROTECT_2 FI_PROTECT_3 FI_PROTECT_3
#define FI_PROTECT_3 FI_PROTECT_4 FI_PROTECT_4
#define FI_PROTECT_4 FI_PROTECT_5 FI_PROTECT_5
#define FI_PROTECT_5 __asm volatile( "b 1b; b 1b;" );

void do_spin_forever();
