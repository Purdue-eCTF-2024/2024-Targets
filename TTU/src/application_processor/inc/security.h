/**
 * @file "security.h"
 * @author TTU
 * @brief Implements constant time comparisons to prevent timing attacks
 * @date 2024
 */

#include <stdbool.h>
#include <stdlib.h>

#ifndef __SECURITY__
#define __SECURITY__

/**
 * @brief This function performs a constant time string comparison
 * 
 * @param s1: char*, string one to compare
 * @param s2: char*, string two to compare
 * 
 * @return bool: true if the strings are equal, false otherwise
*/
bool constant_strcmp(const char *s1, const char *s2);

/**
 * @brief Compare two memory regions in constant time
 * 
 * @param m1: void*, memory region one to compare
 * @param m2: void*, memory region two to compare
 * 
 * @return bool: true if the memory regions are equal, false otherwise
*/
bool constant_memcmp(const void *m1, const void *m2, size_t n);

#endif
