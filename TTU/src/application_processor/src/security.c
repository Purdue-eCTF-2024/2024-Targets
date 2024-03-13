/**
 * @file "security.c"
 * @author TTU
 * @brief Implements constant time comparisons to prevent timing attacks
 * @date 2024
 */

#include "security.h"

// https://nachtimwald.com/2017/04/02/constant-time-string-comparison-in-c/
// https://github.com/chmike/cst_time_memcmp

/**
 * @brief This function performs a constant time string comparison
 * 
 * @param s1: char*, string one to compare
 * @param s2: char*, string two to compare
 * 
 * @return bool: true if the strings are equal, false otherwise
*/
bool constant_strcmp(const char *s1, const char *s2) {
    int             m = 0;
    volatile size_t i = 0;
    volatile size_t j = 0;
    volatile size_t k = 0;

    if (s1 == NULL || s2 == NULL)
        return false;

    while (1) {
        m |= s1[i]^s2[j];

        if (s1[i] == '\0')
            break;
        i++;

        if (s2[j] != '\0')
            j++;
        if (s2[j] == '\0')
            k++;
    }

    return m == 0;
}

/**
 * @brief Compare two memory regions in constant time
 * 
 * @param m1: void*, memory region one to compare
 * @param m2: void*, memory region two to compare
 * 
 * @return bool: true if the memory regions are equal, false otherwise
*/
bool constant_memcmp(const void *m1, const void *m2, size_t n) {
    const unsigned char *pm1 = (const unsigned char*)m1 + n; 
    const unsigned char *pm2 = (const unsigned char*)m2 + n; 
    int res = 0;
    if (n > 0) {
        do {
            int diff = *--pm1 - *--pm2;
            res = (res & (((diff - 1) & ~diff) >> 8)) | diff;
        } while (pm1 != m1);
    }
    int final = ((res - 1) >> 8) + (res >> 8) + 1;
    return final == 0;
}