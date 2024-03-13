/**
 * @file led.h
 * @author Plaid Parliament of Pwning
 * @brief Prototypes for switching leds on and off
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include "stddef.h"

#define LED1 ((size_t)0)
#define LED2 ((size_t)1)
#define LED3 ((size_t)2)

void LED_On(size_t index);

void LED_Off(size_t index);
