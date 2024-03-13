/**
 * @file host_messaging.h
 * @author Plaid Parliament of Pwning
 * @brief Prototypes and macros for host mesagging
 * 
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include "attestation_data.h"

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define print_error_start(x) do { print("%error: "); print(x); } while (0)
#define print_error_end(x) do { print(x); print("%"); } while (0)
#define print_error(x) do { print_error_start(""); print(x); print_error_end(""); } while (0)

#define print_success_start(x) do { print("%success: "); print(x); } while (0)
#define print_success_end(x) do { print(x); print("%"); } while (0)
#define print_success(x) do { print_success_start(""); print(x); print_success_end(""); } while (0)

#define print_debug_start(x) do { print("%debug: "); print(x); } while (0)
#define print_debug_end(x) do { print(x); print("%"); } while (0)
#define print_debug(x) do { print_debug_start(""); print(x); print_debug_end(""); } while (0)
#define print_hex_debug(buf, len) do { print_debug_start(""); print_hex_buf(buf, len); print_debug_end(""); } while (0)

#define print_info_start(x) do { print("%info: "); print(x); } while (0)
#define print_info_end(x) do { print(x); print("%"); } while (0)
#define print_info(x) do { print_info_start(""); print(x); print_info_end(""); } while (0)

#define print_ack() do { print("%ack%\n"); } while (0)

 /**
  * @brief IMPORTANT: this can NOT be printf
  */
void print(const char *msg);

void printn(const char *msg, uint8_t maxlen);

void print_attestation_data(uint32_t c_id, att_data_t *att_data);

void print_component_boot(uint32_t c_id, const char *boot_msg);

int read_hex(const char *buf, size_t bufsz, uint32_t *value);

void print_ap_boot(const char *boot_msg);

void recv_input(const char *msg, char *buf, size_t maxlen, bool include_ack);

void print_hex(const uint8_t *buf, size_t len);

void print_hex_integer(uint32_t val, bool pad);

void uint32_to_hex(uint32_t val, char *buf);

int printf(const char *format, ...);
