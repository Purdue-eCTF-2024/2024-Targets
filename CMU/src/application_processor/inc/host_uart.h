/**
 * @file host_uart.h
 * @author Plaid Parliament of Pwning
 * @brief Prototypes for UART messaging
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once
#include <stdint.h>

/**
 * @brief UART instance to use for console
 */
#define CONSOLE_UART (0)

/**
 * @brief Console baud rate
 */
#define CONSOLE_BAUD ((uint32_t)115200)  

void uart_write(uint8_t c);

uint8_t uart_read(void);

void uart_putchar(char c);

char uart_getchar(void);

int uart_puts(const char *s);
