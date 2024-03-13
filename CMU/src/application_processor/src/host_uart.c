/**
 * @file host_uart.c
 * @author Plaid Parliament of Pwning
 * @brief Functions to read/write to UART
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include "host_uart.h"
#include "uart.h"

#define MXC_UARTn MXC_UART_GET_UART(CONSOLE_UART)
#define UART_FIFO MXC_UART_GET_FIFO(CONSOLE_UART)

/**
 * @brief Blocking write a byte to UART
 * 
 * @param c byte to write
 */
void uart_write(uint8_t c) {
	// Wait until there's room in the FIFO
	while (MXC_UART_GetTXFIFOAvailable(MXC_UARTn) == 0) {}

	MXC_UART_WriteCharacter(MXC_UARTn, c);
}

/**
 * @brief Read a byte from UART
 * 
 * @return byte read
 */
uint8_t uart_read(void) {
    uint8_t c = MXC_UART_ReadCharacter(MXC_UARTn);
    uart_write(c); // echo the character back
    return c;
}

/**
 * @brief Print a character to UART
 * 
 * Transforms LF to CRLF.
 * 
 * @param c character to print
 */
void uart_putchar(char c) {
    if (c == '\n') {
        uart_write('\r');
    }
    uart_write(c);
}

/**
 * @brief Read a character from UART
 * 
 * Transforms CR to LF.
 *
 * @return character read
 */
char uart_getchar(void) {
    uint8_t c = uart_read();
    if (c == '\r') {
        return '\n';
    } else {
        return c;
    }
}

/**
 * @brief Print a string to UART
 * 
 * Write a null-terminated string to the host.
 * Transforms LF to CRLF.
 * 
 * @param s string to print
 * @return number of characters written to UART
 */
int uart_puts(const char *s) {
    int written_count = 0;
	while (*s != 0) {
        if (*s == '\r') {
            ++written_count;
        }

        uart_putchar(*s++);
        ++written_count;
	}
    return written_count;
}