/**
 * @file fiproc.h
 * @author Plaid Parliament of Pwning
 * @brief Prototypes for fault injection protections
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#pragma once

#define FIPROC_DELAY_WRAP() fiproc_delay()

void fiproc_load_pool();

int fiproc_delay();

int fiproc_ranged_delay();
