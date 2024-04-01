#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <stdint.h>

/* state */
typedef struct sha512_context_ {
    uint64_t  length, state[8];
    size_t curlen;
    unsigned char buf[128];
} sha512_context;

int sha512_init(sha512_context *md);
int sha512_final(sha512_context *md, unsigned char *out);
int sha512_update(sha512_context *md, const unsigned char *in, size_t inlen);
int sha512(const unsigned char *message, size_t message_len, unsigned char *out);

// void sha512(uint512 *out, const unsigned char *in, size_t inlen);
// void sha512(uint512 *out, const unsigned char *in, size_t inlen) {
//     sha512_context ctx;
//     sha512_init(&ctx);
//     sha512_update(&ctx, in, inlen);
//     sha512_final(&ctx, out->byte);
// }

#endif