#include "wolfssl/wolfssl/ssl.h"

#ifndef MAX_RECORD_SIZE
#define MAX_RECORD_SIZE (8 * 1024)
#endif

typedef struct {
    int curr_index;
    int data_len;
    char buf[MAX_RECORD_SIZE];
    i2c_addr_t addr;
} tls13_buf;

int i2cwolf_receive(WOLFSSL* ssl, char* buf, int sz, void* ctx);
int i2cwolf_send(WOLFSSL* ssl, char* buf, int sz, void* ctx);
tls13_buf* ssl_new_buf(i2c_addr_t addr);
WOLFSSL_CTX* ssl_new_context_client();
WOLFSSL_CTX* ssl_new_context_server();
WOLFSSL* ssl_new_session(WOLFSSL_CTX *ctx, tls13_buf *tbuf);
int ssl_handshake_client(WOLFSSL *ssl, tls13_buf *tbuf);
int ssl_handshake_server(WOLFSSL *ssl, tls13_buf *tbuf);
void ssl_free_all(WOLFSSL_CTX *ctx, WOLFSSL *ssl, tls13_buf *tbuf);