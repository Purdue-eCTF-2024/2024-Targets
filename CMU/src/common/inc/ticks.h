/**
 * @file ticks.h
 * @author Plaid Parliament of Pwning
 * @brief Prototypes for timer
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

void tick_init();

uint32_t get_ticks();
