/**
 * @file "trng_wrapper.h"
 * @author Kevin Marquis
 * @brief Simplified TRNG API Header
 * @date 2024
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "trng.h"

#define TRNG_DEMO 1

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Uses built in TRNG to generate a random unsigned integer.
 * 
 *  @return Random unsigned integer.
 * 
 *  @note The TRNG must first be initialized with a call to MXC_TRNG_Init().
 *        Once done with the TRNG, use MXC_TRNG_Shutdown().
*/
unsigned int trng_gen_uint();