/**
 * @file libc_mu.c
 * @author Plaid Parliament of Pwning
 * @brief Implements a very small subset of libc
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include "libc_mu.h"

#if IS_AP
#include "host_uart.h"
#endif

#include <stdint.h>

/**
 * @brief Compares two null terminated strings
 * 
 * @param l string 1
 * @param r string 2
 * @return the difference between the first unmatched character
 */
int strcmp(const char *l, const char *r) {
	// Stolen from MUSL http://git.musl-libc.org/cgit%2Fmusl%2Ftree%2Fsrc%2Fstring%2Fstrcmp.c%2F
	for (; *l==*r && *l; l++, r++);
	return *(unsigned char *)l - *(unsigned char *)r;
}

/**
 * @brief Copies a null terminated string from src to dst
 * 
 * @param dst dst address
 * @param src src address
 * @return address of the new string
 */
char *strcpy(char *dst, const char *src) {
	// Stolen from MUSL https://github.com/esmil/musl/blob/master/src/string/strcpy.c
	const char *s = src;
	char *d = dst;
	while ((*d++ = *s++));
	return dst;
}

/**
 * @brief Calculates the length of a null terminated string
 * 
 * @param s string 
 * @return length of the string
 */
size_t strlen(const char *s) {
	// Stolen from MUSL https://github.com/esmil/musl/blob/master/src/string/strlen.c
	const char *a = s;
	for (; *s; s++);
	return s-a;
}

#if IS_AP
int puts(const char *s) {
	return uart_puts(s);
}
#endif

/**
 * @brief Sets all values in buffer to a constant
 * 
 * @param b pointer to buffer
 * @param c constant
 * @param len length of buffer
 * @return pointer to buffer
 */
void *memset(void *b, int c, size_t len) {
	uint8_t *p = (uint8_t *)b;
	for (size_t i = 0; i < len; ++i) {
		p[i] = c;
	}
	return b;
}

/**
 * @brief Copies bytes from src to dst
 * 
 * @param dst dst buffer
 * @param src src buffer
 * @param n number of bytes to copy
 * @return pointer to dst buffer
 */
void *memcpy(void *restrict dst, const void *restrict src, size_t n) {
	uint8_t *d = (uint8_t *)dst;
	const uint8_t *s = (const uint8_t *)src;
	for (size_t i = 0; i < n; ++i) {
		d[i] = s[i];
	}
	return dst;
}

/**
 * @brief Compares two buffers
 * 
 * @param vl buffer 1
 * @param vr buffer 2
 * @param n number of bytes to compare
 * @return 0 or difference between the first byte that is different
 */
int memcmp(const void *vl, const void *vr, size_t n) {
    // Stolen from MUSL https://github.com/esmil/musl/blob/master/src/string/memcmp.c
	const unsigned char *l=vl, *r=vr;
	for (; n && *l == *r; n--, l++, r++);
	return n ? *l-*r : 0;
}
