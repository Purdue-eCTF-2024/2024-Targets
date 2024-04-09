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

// Print a message through USB UART and then receive a line over USB UART
void recv_input(const char *msg, char *buf, size_t buf_size) {
    print_debug(msg);
    fflush(stdout); // Use stdout to ensure it's flushing the standard output stream
    print_ack();
    fgets(buf, buf_size, stdin); // Using fgets to safely read the input
    // Remove newline character if fgets stops reading because of a newline character
    if (strchr(buf, '\n')) {
        *strchr(buf, '\n') = '\0';
    } else {
        // Clear stdin to discard characters beyond buf_size - 1
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {}
    }

    if (strlen(buf) > buf_size - 2) { // Adjust this value based on specific needs
        print_error("Input too long");
        // Optionally, clear the buffer to prevent processing of this input
        memset(buf, 0, buf_size); // This line clears the buffer if the input is too long
    }
    puts("");
}


// Prints a buffer of bytes as a hex string
void print_hex(uint8_t *buf, size_t len) {
    for (int i = 0; i < len; i++)
    	printf("%02x", buf[i]);
    printf("\n");
}
