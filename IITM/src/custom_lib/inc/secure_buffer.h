#ifndef SECURE_BUFFER_H
#define SECURE_BUFFER_H

#include "helper_functions.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
// Using macros instead of functions to initialise in stack memory

// For uint32_t type
#define INIT_BUF_U32(buf, n)                                                   \
    uint32_t CONCAT(internal_buffer_, buf)[n];                                 \
    buf_u32 buf = {.data = CONCAT(internal_buffer_, buf), .size = n}

// Volatile buffer

#define INIT_VOL_BUF_U32(buf, n)                                               \
    uint32_t CONCAT(internal_buffer_, buf)[n];                                 \
    volatile buf_u32 buf = {.data = CONCAT(internal_buffer_, buf), .size = n}

typedef struct buf_u32 {
    uint32_t size;
    uint32_t *data;
} buf_u32;

/**
 * Access a uint from a buffer with bounds checks.
 */
uint32_t access_u32(const buf_u32 buf, uint32_t index);
/**
 * Constant-time compare two buffers.
 *
 * @return `true` if equal
 */
bool cmp_bu32(const buf_u32 buf1, const buf_u32 buf2);
/**
 * Set a uint in a buffer with bounds checks.
 */
void set_u32(buf_u32 buf, uint32_t index, uint32_t value);
/**
 * Copy ints from a pointer into a secure buffer.
 */
void cpyin_raw_bu32(buf_u32 dst, uint8_t *src, uint32_t count);
/**
 * Copy ints from a secure buffer to a pointer.
 */
void cpyout_raw_bu32(uint8_t *dst, buf_u32 src, uint32_t count);
/**
 * Copy a buffer into another.
 */
void cpy_bu32(buf_u32 dst, const buf_u32 src, uint32_t count);
/**
 * Take a memory slice of a buffer.
 */
buf_u32 slice_bu32(const buf_u32 src, uint32_t i, uint32_t j);
/**
 * Panic if a buffer's size is less than `size`.
 */
void assert_min_size_bu32(const buf_u32 buf, uint32_t size);
/**
 * Panic if a buffer's size is not equal to `size`.
 */
void assert_size_exact_bu32(const buf_u32 buf, uint32_t size);
/**
 * Concatenate `a` and `b`, and store it in `out`.
 */
uint32_t concat_bu32(const buf_u32 a, const buf_u32 b, buf_u32 out);

// For uint8_t type
#define INIT_BUF_U8(buf, n)                                                    \
    uint8_t CONCAT(internal_buffer_, buf)[n];                                  \
    buf_u8 buf = {.data = CONCAT(internal_buffer_, buf), .size = n}

// Volatile buffer
#define INIT_VOL_BUF_U8(buf, n)                                                \
    uint8_t CONCAT(internal_buffer_, buf)[n];                                  \
    volatile buf_u8 buf = {.data = CONCAT(internal_buffer_, buf), .size = n}

typedef struct buf_u8 {
    uint32_t size;
    uint8_t *data;
} buf_u8;

/**
 * Access a byte from a buffer with bounds checks.
 */
uint8_t access_u8(const buf_u8 buf, uint32_t index);
/**
 * Constant-time compare two buffers.
 *
 * @return `true` if equal
 */
bool cmp_bu8(const buf_u8 buf1, const buf_u8 buf2);
/**
 * Set a byte in a buffer with bounds checks.
 */
void set_u8(buf_u8 buf, uint32_t index, uint8_t value);
/**
 * Copy bytes from a pointer into a secure buffer.
 */
void cpyin_raw_bu8(buf_u8 dst, uint8_t *src, uint32_t count);
/**
 * Copy bytes from a secure buffer to a pointer.
 */
void cpyout_raw_bu8(uint8_t *dst, buf_u8 src, uint32_t count);
/**
 * Copy a buffer into another.
 */
void cpy_bu8(buf_u8 dst, const buf_u8 src, uint32_t count);
/**
 * Take a memory slice of a buffer.
 */
buf_u8 slice_bu8(const buf_u8 src, uint32_t i, uint32_t j);
/**
 * Panic if a buffer's size is less than `size`.
 */
void assert_min_size_bu8(const buf_u8 buf, uint32_t size);
/**
 * Panic if a buffer's size is not equal to `size`.
 */
void assert_size_exact_bu8(const buf_u8 buf, uint32_t size);
/**
 * Concatenate `a` and `b`, and store it in `out`.
 */
uint32_t concat_bu8(const buf_u8 a, const buf_u8 b, buf_u8 out);

#endif
