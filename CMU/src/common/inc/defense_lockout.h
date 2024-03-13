/**
 * @file defense_lockout.c
 * @author Plaid Parliament of Pwning
 * @brief Function prototypes for defensive lockout with a reset prevention canary
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once
#include <stdbool.h>

void defense_lockout_init();

void defense_lockout_start();

void defense_lockout_clear(bool delay);
