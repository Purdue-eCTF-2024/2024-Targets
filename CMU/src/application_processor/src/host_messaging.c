/**
 * @file host_messaging.c
 * @author Plaid Parliament of Pwning
 * @brief Implements messaging from the host computer to/from application processor
 * 
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */

#include "host_messaging.h"
#include "host_uart.h"
#include "libc_mu.h"
#include "util.h"

#include <stdarg.h>

/**
 * @brief Print a single byte as hex
 * 
 * @param x single byte
 */
void _print_hex_byte(uint8_t x) {
    char *hexchars = "0123456789abcdef";
    uart_putchar(hexchars[(x >> 4) & 0xF]);
    uart_putchar(hexchars[(x >> 0) & 0xF]);
}

/**
 * @brief Reads input from the host computer
 * 
 * Print a message through USB UART and then receive a line over USB UART
 * Always returns a null-terminated buffer.
 * Reads up to `maxlen-1` bytes to leave space for null term
 * 
 * @param msg debug msg to be printed
 * @param buf buffer to fill the input into 
 * @param maxlen max length of the input that can be taken including null term
 * @param include_ack whether to print an ack or not
 */
void recv_input(const char *msg, char *buf, size_t maxlen, bool include_ack) {
    print_debug(msg);
    if (include_ack) print_ack();
    
    memset(buf, 0, maxlen);

    // Terminate the string at the first nonprintable char,
    // stop 1 character early to ensure we don't overwrite the null.
    for (int i = 0; i < maxlen - 1; i++) {
        uint8_t c = uart_read();

        // Deal with CRLFs
        while ((i == 0) && (c < 0x20 || c > 0x7E)) {
            c = uart_read();
        }

        if (c < 0x20 || c > 0x7E) {
            buf[i] = 0;
            break;
        } else {
            buf[i] = c;
        }
    }
    uart_putchar('\n');
}

/**
 * @brief Prints a buffer of bytes as a hex string
 * 
 * @param buf buffer
 * @param len length 
 */
void print_hex_buf(const uint8_t *buf, size_t len) {
    for (int i = 0; i < len; i++) {
        _print_hex_byte(buf[i]);
        uart_putchar(' ');
    }
    uart_putchar('\n');
}

/**
 * @brief Print a hex integer value
 * 
 * @param val value to print
 * @param pad add padding to make 8 char long
 */
void print_hex_integer(uint32_t val, bool pad) {
    uint8_t x;

    print("0x");

    x = (val >> 24) & 0xFF;
    if (pad || (x != 0)) {
        _print_hex_byte(x);
        pad = true; 
    }

    x = (val >> 16) & 0xFF;
    if (pad || (x != 0)) {
        _print_hex_byte(x);
        pad = true;
    }

    x = (val >> 8) & 0xFF;
    if (pad || (x != 0)) {
        _print_hex_byte(x);
        pad = true;
    }

    x = (val >> 0) & 0xFF;
    _print_hex_byte(x);
}

/**
 * @brief Prints null terminated strings
 * 
 * @param msg message
 */
void print(const char *msg) {
    while (*msg) {
        uart_putchar(*(msg++));
    }
}

/**
 * @brief Print a message to the UART, stopping at either a \0 or at maxlen bytes, whichever comes first
 * 
 * @param msg message
 * @param maxlen max length of the message
 */
void printn(const char *msg, uint8_t maxlen) {
    for (; *msg && maxlen; ++msg, --maxlen) {
        uart_putchar(*msg);
    }
}

/**
 * @brief Prints attestation data
 * 
 * @param c_id component id
 * @param att_data attestation data buffer
 */
void print_attestation_data(uint32_t c_id, att_data_t *att_data) {
    print_info_start("C>");
    print_hex_integer(c_id, true);
    print_info_end("\n");

    print_info_start("LOC>");
    printn(att_data->location, ATTEST_INFO_LEN);
    print("\n");

    print("DATE>");
    printn(att_data->date, ATTEST_INFO_LEN);
    print("\n");

    print("CUST>");
    printn(att_data->customer, ATTEST_INFO_LEN);
    print_info_end("\n");
}

/**
 * @brief Prints component's boot message
 * 
 * @param c_id component id
 * @param boot_msg boot message
 */
void print_component_boot(uint32_t c_id, const char *boot_msg) {
    print_info_start("");
    print_hex_integer(c_id, true);
    print(">");
    printn(boot_msg, BOOT_MSG_LEN);
    print_info_end("\n");
}

/**
 * @brief Prints AP's boot message
 * 
 * @param boot_msg boot message
 */
void print_ap_boot(const char *boot_msg) {
    print_info_start("AP>");
    printn(boot_msg, BOOT_MSG_LEN);
    print_info_end("\n");

    print_success("Boot\n");
}

/**
 * @brief Converts a hex character to int
 * 
 * @param c character
 * @return int on success, negative on error
 */
int from_hex_digit(char c) {
    if ('0' <= c && c <= '9') {
        return c - '0';
    } else if ('a' <= c && c <= 'f') {
        return c - 'a' + 0xA;
    } else if ('A' <= c && c <= 'F') {
        return c - 'A' + 0xA;
    } else {
        return ERROR_RETURN;
    }
}

/**
 * @brief Converts a hex string to an int
 * 
 * @param buf number string
 * @param bufsz buffer size
 * @param value output value
 * @return int 0 on success, negative on error
 */
int read_hex(const char *buf, size_t bufsz, uint32_t *value) {
    if (bufsz == 0 || *buf != '0') {
        return ERROR_RETURN;
    }
    ++buf; --bufsz;

    if (bufsz == 0 || (*buf != 'x' && *buf != 'X')) {
        return ERROR_RETURN;
    }
    ++buf; --bufsz;

    uint32_t result = 0;

    int i;
    for (i = 0; i < 8; ++i) {
        if (bufsz == 0) {
            break;
        }
        int digit = from_hex_digit(*buf);
        if (digit == -1) {
            break;
        }
        ++buf; --bufsz;

        result <<= 4;
        result |= digit;
    }

    if (i == 0) {
        // 0x by itself is not a valid number
        return ERROR_RETURN;
    }

    if (bufsz == 0 || *buf == '\0') {
        *value = result;
        return SUCCESS_RETURN;
    } else {
        // Trailing data
        return ERROR_RETURN;
    }
}

/**
 * @brief Custom printf that only handles strings
 * 
 * @param format format string
 * @param ... variable arg params
 * @return number of bytes printed of positive, negative on error
 */
int printf(const char *format, ...) {
    va_list args;
    va_start(args, format);

    int written_count = 0;

    while (*format != '\0') {
        char c = *format++;
        if (c == '%') {
            switch (*format++) {
            case '%': {
                uart_putchar('%');
                written_count += 1;
                break;
            }
            case 's': {
                const char *s = va_arg(args, const char *);
                written_count += uart_puts(s);
                break;
            }
            default:
                // There is no sane way to handle a format argument we don't recognize,
                // except by giving up.
                va_end(args);
                return -1;
            }
        } else {
            uart_putchar(c);
            written_count += 1;
        }
    }
    
    va_end(args);

    return written_count;
}
