#include <icc.h>
#include <stdio.h>

#include "board_link.h"
#include "wolfssl_rxtx.h"
#include "wolfssl/wolfssl/ssl.h"
#include "secrets_component.h"


/**
 * @brief Callback used by WolfSSL to handle IO receive requests
 * 
 * @param ssl: WOLFSSL*, WolfSSL session
 * @param buf: char*, pointer to an internal WolfSSL buffer
 * @param sz: int, number of bytes requested by WolfSSL for this execution of the callback
 * @param ctx: void*, pointer to a user-defined data structure provided during ssl session creation
 * 
 * @return int: Number of bytes requested by wolfSSL
*/
int __attribute__((noinline, optimize(0))) i2cwolf_receive(WOLFSSL* ssl, char* buf, int sz, void* ctx) {

    tls13_buf *tb = ctx;

    if (tb->curr_index == 0) {
        XMEMSET(tb->buf, 0, MAX_RECORD_SIZE);
        // Ensure I2C register flags have expected value.
        // Sometimes these are not set properly
        I2C_REGS[RECEIVE_DONE][0] = false;
        I2C_REGS[TRANSMIT_DONE][0] = false;
        int len = wait_and_receive_packet((uint8_t *)tb->buf);

        if (len < 0)
            return ERROR_RETURN;
            
        tb->data_len = len;
    }

    // Handle the case where sz > MAX_I2C_MESSAGE_LEN
    while (tb->data_len < (sz + tb->curr_index)) {
        // Ensure I2C register flags have expected value.
        // Sometimes these are not set properly
        I2C_REGS[RECEIVE_DONE][0] = false;
        I2C_REGS[TRANSMIT_DONE][0] = false;
        int len = wait_and_receive_packet((uint8_t *)(tb->buf + tb->data_len));

        if (len < 0)
            return ERROR_RETURN;

        tb->data_len += len;
    }

    // Copy 'sz' bytes from intermediate buffer
    // into buffer managed by wolfSSL
    XMEMCPY(buf, tb->buf + tb->curr_index, sz);
    tb->curr_index += sz;

    // If the last portion of the buffer was just read,
    // set the curr_index to 0 to reset the state.
    if (tb->curr_index == tb->data_len) {
        tb->curr_index = 0;
    }

    // Ensure I2C register flags have expected value.
    // Sometimes these are not set properly
    I2C_REGS[RECEIVE_DONE][0] = false;
    I2C_REGS[TRANSMIT_DONE][0] = false;
    return sz;
}

/**
 * @brief Callback used by WolfSSL to handle IO send requests
 * 
 * @param ssl: WOLFSSL*, WolfSSL session
 * @param buf: char*, pointer to an internal WolfSSL buffer
 * @param sz: int, number of bytes requested by WolfSSL for this execution of the callback
 * @param ctx: void*, pointer to a user-defined data structure provided during ssl session creation
 * 
 * @return int: Number of bytes requested to be sent by wolfSSL
*/
int __attribute__((noinline, optimize(0))) i2cwolf_send(WOLFSSL* ssl, char* buf, int sz, void* ctx) {

    int ret = sz;
    (void)ctx;

    int i = 0;
    uint16_t len = (uint16_t)sz;

    // Handle the case where sz > MAX_I2C_MESSAGE_LEN
    while (len > MAX_I2C_MESSAGE_LEN-1) {
        // Ensure I2C register flags have expected value.
        // Sometimes these are not set properly
        I2C_REGS[RECEIVE_DONE][0] = true;
        I2C_REGS[TRANSMIT_DONE][0] = false;
        send_packet_and_ack(MAX_I2C_MESSAGE_LEN-1, (uint8_t *)(buf + i));
        I2C_REGS[TRANSMIT_DONE][0] = true;
        len -= MAX_I2C_MESSAGE_LEN-1;
        i += MAX_I2C_MESSAGE_LEN-1;
    }

    if (len == 0)
        return ret;

    // Ensure I2C register flags have expected value.
    // Sometimes these are not set properly
    I2C_REGS[RECEIVE_DONE][0] = true;
    I2C_REGS[TRANSMIT_DONE][0] = false;
    send_packet_and_ack(len, (uint8_t *)(buf + i));
    I2C_REGS[TRANSMIT_DONE][0] = true;
    
    return ret;
}

/**
 * @brief Creates and initializes a new tls13_buf object
 * 
 * @param i2c_addr_t addr: The address of the component to be communicated with
 * 
 * @return tls13_buf*: Pointer to the created object
*/
tls13_buf* __attribute__((noinline, optimize(0))) ssl_new_buf(i2c_addr_t addr) {
    tls13_buf *tbuf = (tls13_buf *)malloc(sizeof(tls13_buf));
    XMEMSET(tbuf, 0, sizeof(tls13_buf));
    tbuf->addr = addr;

    return tbuf;
}

/**
 * @brief Creates and initializes a new wolfSSL 'server' context
 * 
 * @return WOLFSSL_CTX*: Pointer to the created object
*/
WOLFSSL_CTX* __attribute__((noinline, optimize(0))) ssl_new_context_server() {
    WOLFSSL_CTX* ctx;
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if(ctx == NULL) {
        return NULL;
    }

    // Set callbacks
    wolfSSL_CTX_SetIOSend(ctx, i2cwolf_send);
    wolfSSL_CTX_SetIORecv(ctx, i2cwolf_receive); 

    wolfSSL_CTX_use_PrivateKey_buffer(ctx, (const unsigned char*)KEY_DEVICE, sizeof(KEY_DEVICE), SSL_FILETYPE_PEM);
    wolfSSL_CTX_use_certificate_buffer(ctx, (const unsigned char*)PEM_DEVICE, sizeof(PEM_DEVICE), SSL_FILETYPE_PEM);

    // Restrict cipher
    int cipherlist = wolfSSL_CTX_set_cipher_list(ctx, "TLS13-AES128-GCM-SHA256");
    if(cipherlist != WOLFSSL_SUCCESS) {
        return NULL;
    }

    int verify_buffer = wolfSSL_CTX_load_verify_buffer(ctx, (const unsigned char*)PEM_CA, sizeof(PEM_CA), SSL_FILETYPE_PEM);
    
    if(verify_buffer != WOLFSSL_SUCCESS) {
        return NULL;
    }

    // Load rootCA cert into verify buffer
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_CLIENT_ONCE, NULL);

    return ctx;
}

/**
 * @brief Creates and initializes a new wolfSSL session
 * 
 * @param WOLFSSL_CTX*: Pointer to a previoulsy created wolfSSL context object
 * @param tls13_buf*: Pointer to a previoulsy created tls13_buf object  
 * 
 * @return WOLFSSL*: Returns a new wolfSSL session
*/
WOLFSSL* __attribute__((noinline, optimize(0))) ssl_new_session(WOLFSSL_CTX *ctx, tls13_buf *tbuf) {
    WOLFSSL *ssl;
    ssl = wolfSSL_new(ctx);
    if(ssl == 0) {
        wolfSSL_CTX_free(ctx);
        return NULL;
    }

    // Add pointer to 'tbuf' to callbacks
    wolfSSL_SetIOReadCtx(ssl, tbuf);
    wolfSSL_SetIOWriteCtx(ssl, tbuf);

    return ssl;
}

/**
 * @brief Performs a server SSL handshake
 * 
 * @param WOLFSSL_CTX*: Pointer to a previoulsy created wolfSSL context object
 * @param tls13_buf*: Pointer to a previoulsy created tls13_buf object  
 * 
 * @return int: Either WOLFSSL_SUCCESS or WOLFSSL_ERROR
*/
int __attribute__((noinline, optimize(0))) ssl_handshake_server(WOLFSSL *ssl, tls13_buf *tbuf) {
    int ret = 0;
    int err = 0;

    // Re-enable the instruction cache for handshake.
    // With this enabled, handshake is too slow for 
    // competition constraints
    MXC_ICC_Enable(MXC_ICC0);

    do {
        ret = wolfSSL_accept(ssl);
        err = wolfSSL_get_error(ssl, ret);
    } while (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE);
    if (ret != WOLFSSL_SUCCESS) {
        return ERROR_RETURN;
    }

    // Disable the instruction cache
    MXC_ICC_Disable(MXC_ICC0);

    // Reset communication state
    tbuf->curr_index = 0;
    tbuf->data_len = 0;
    I2C_REGS[RECEIVE_DONE][0] = false;
    I2C_REGS[TRANSMIT_DONE][0] = true;

    return WOLFSSL_SUCCESS;
}

/**
 * @brief Frees all objects created and used in the SSL communication
 * 
 * @param WOLFSSL_CTX*: Pointer to a previoulsy created wolfSSL context object
 * @param WOLFSSL*: Pointer to a previoulsy created wolfSSL session object
 * @param tls13_buf*: Pointer to a previoulsy created tls13_buf object  
*/
void ssl_free_all(WOLFSSL_CTX *ctx, WOLFSSL *ssl, tls13_buf *tbuf) {
    wolfSSL_CTX_free(ctx);
    wolfSSL_free(ssl);
    free(tbuf);
}
