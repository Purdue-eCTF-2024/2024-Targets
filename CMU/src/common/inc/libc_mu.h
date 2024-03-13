/**
 * @file libc_mu.h
 * @author Plaid Parliament of Pwning
 * @brief A very small subset of libc
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include <stddef.h>

int strcmp(const char *s1, const char *s2);

char *strcpy(char *dst, const char *src);

size_t strlen(const char *s);

#if IS_AP
int puts(const char *s);
#endif

void *memset(void *b, int c, size_t len);

void *memcpy(void *restrict dst, const void *restrict src, size_t n);

int memcmp(const void *vl, const void *vr, size_t n);
