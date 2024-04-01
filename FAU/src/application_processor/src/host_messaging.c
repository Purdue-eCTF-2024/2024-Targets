/**
 * @file host_messaging.c
 * @author Frederich Stine
 * @brief eCTF Host Messaging Implementation 
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */


#include "host_messaging.h"
#include "wolfssl/wolfssl/ssl.h"
#include <stdlib.h>
#include <string.h>

#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

// Print a message through USB UART and then receive a line over USB UART
int recv_input(const char *msg, char *buf, size_t len) {
    print_debug("%s", msg);
    fflush(0);
    print_ack();
    if(fgets(buf, len + 1, stdin) != NULL) {
        size_t in_len = strlen(buf);
        if (in_len > 0 && buf[in_len - 1] == '\n') {
                buf[in_len - 1] = '\0';
        }
    } else {
        return ERROR_RETURN;
    }
        // gets(buf);
    puts("");
    return SUCCESS_RETURN;
}

// Prints a buffer of bytes as a hex string
void print_hex(uint8_t *buf, size_t len) {
    for (int i = 0; i < len; i++)
    	printf("%02x", buf[i]);
    printf("\n");
}
