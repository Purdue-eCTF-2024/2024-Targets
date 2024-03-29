#include "secure_buffer.h"
#include "helper_functions.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// #include <panic.h>
//  typedef struct buf_u32 buf_u32;
//  typedef struct buffer_uint8 buffer_uint8;

// For uint32_t type
uint32_t access_u32(buf_u32 buf, uint32_t index) {
    if (index < 0 || index >= buf.size) {
        panic();
    }
    return buf.data[index];
}

// Timing attack possible because of compiler optimisations. Do use hash
// functions
bool cmp_bu32(buf_u32 buf1, buf_u32 buf2) {

    bool result = true;
    if (buf1.size != buf2.size) {
        result = result && false;
    } else {
        result = result && true;
    }
    for (uint32_t i = 0; i < buf1.size; i++) {
        // Instead compare the hashes of the buffers
        if (buf1.data[i] != buf2.data[i]) {
            result = result && false;
        } else {
            result = result && true;
        }
    }
    return result;
}

void set_u32(buf_u32 buf, uint32_t index, uint32_t value) {
    if (index < 0 || index >= buf.size) {
        panic();
    }
    buf.data[index] = value;
}

void cpyin_raw_bu32(buf_u32 dst, uint8_t *src, uint32_t count) {
    assert_min_size_bu32(dst, count);
    memcpy(dst.data, src, count * sizeof(uint32_t));
}

void cpyout_raw_bu32(uint8_t *dst, buf_u32 src, uint32_t count) {
    assert_min_size_bu32(src, count);
    memcpy(dst, src.data, count * sizeof(uint32_t));
}

void cpy_bu32(buf_u32 dst, buf_u32 src, uint32_t count) {
    assert_min_size_bu32(src, count);
    assert_min_size_bu32(dst, count);
    memcpy(dst.data, src.data, count * sizeof(uint32_t));
}

buf_u32 slice_bu32(buf_u32 src, uint32_t i, uint32_t j) {
    buf_u32 new;
    if (i > j) {
        panic();
    }
    assert_min_size_bu32(src, j);
    new.data = &src.data[i];
    new.size = j - i;
    return new;
}

void assert_min_size_bu32(buf_u32 buf, uint32_t size) {
    if (buf.size < size) {
        panic();
    }
}

void assert_size_exact_bu32(buf_u32 buf, uint32_t size) {
    if (buf.size != size) {
        panic();
    }
}

uint32_t concat_bu32(buf_u32 a, buf_u32 b, buf_u32 out) {
    assert_min_size_bu32(out, a.size + b.size);
    INIT_BUF_U32(tmp_buf, a.size + b.size);
    cpy_bu32(tmp_buf, a, a.size);
    cpy_bu32(slice_bu32(tmp_buf, a.size, a.size + b.size), b, b.size);
    cpy_bu32(out, tmp_buf, a.size + b.size);
    return a.size + b.size;
}

// For uint8_t type

uint8_t access_u8(buf_u8 buf, uint32_t index) {

    if (index < 0 || index >= buf.size) {
        panic();
    }
    return buf.data[index];
}

// Timing attack possible because of compiler optimisations. Do use hash
// functions
bool cmp_bu8(buf_u8 buf1, buf_u8 buf2) {
    bool result = true;
    if (buf1.size != buf2.size) {
        result = result && false;
    } else {
        result = result && true;
    }
    spin();
    for (uint32_t i = 0; i < buf1.size; i++) {
        // Instead compare the hashes of the buffers
        if (buf1.data[i] != buf2.data[i]) {
            result = result && false;
        } else {
            result = result && true;
        }
    }
    return result;
}

void set_u8(buf_u8 buf, uint32_t index, uint8_t value) {
    if (index < 0 || index >= buf.size) {
        panic();
    }
    buf.data[index] = value;
}

void cpyin_raw_bu8(buf_u8 dst, uint8_t *src, uint32_t count) {
    assert_min_size_bu8(dst, count);
    memcpy(dst.data, src, count * sizeof(uint8_t));
}

void cpyout_raw_bu8(uint8_t *dst, buf_u8 src, uint32_t count) {
    assert_min_size_bu8(src, count);
    memcpy(dst, src.data, count * sizeof(uint8_t));
}

void cpy_bu8(buf_u8 dst, buf_u8 src, uint32_t count) {
    assert_min_size_bu8(src, count);
    assert_min_size_bu8(dst, count);
    memcpy(dst.data, src.data, count * sizeof(uint8_t));
}

buf_u8 slice_bu8(buf_u8 src, uint32_t i, uint32_t j) {
    buf_u8 new;
    if (i > j) {
        panic();
    }
    assert_min_size_bu8(src, j);
    new.data = &src.data[i];
    new.size = j - i;
    return new;
}

void assert_min_size_bu8(buf_u8 buf, uint32_t size) {
    if (buf.size < size) {
        panic();
    }
}

void assert_size_exact_bu8(buf_u8 buf, uint32_t size) {
    if (buf.size != size) {
        panic();
    }
}

uint32_t concat_bu8(buf_u8 a, buf_u8 b, buf_u8 out) {
    assert_min_size_bu8(out, a.size + b.size);
    INIT_BUF_U8(tmp_buf, a.size + b.size);
    cpy_bu8(tmp_buf, a, a.size);
    cpy_bu8(slice_bu8(tmp_buf, a.size, a.size + b.size), b, b.size);
    cpy_bu8(out, tmp_buf, a.size + b.size);
    return a.size + b.size;
}
