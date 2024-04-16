/**
 * @file "simple_trng.c"
 * @author Kevin Marquis
 * @brief Simplified TRNG API Implementation
 * @date 2024
*/

#include "simple_trng.h"

/** @brief Uses built in TRNG to generate a random unsigned integer.
 * 
 *  @return Random unsigned integer.
 * 
 *  @note The TRNG must first be initialized with a call to MXC_TRNG_Init().
 *        Once done with the TRNG, use MXC_TRNG_Shutdown().
*/
unsigned int trng_gen_uint(){
    unsigned int random;
    MXC_TRNG_Random(&random, sizeof(unsigned int));
    return random;
}