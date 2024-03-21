/**
 * @file "ap_session.h"
 * @brief Session-related functions for AP
 */

#ifndef _AP_SESSION_H_
#define _AP_SESSION_H_

#include "ap_common.h"

// Initialize session struct
void session_init(void);

// Validate a session exists for a given component_id
// if not, make one
int validate_session(mit_comp_id_t component_id);

// Get ptr to session of given component_id
mit_session_t * get_session_of_component(mit_comp_id_t component_id);

#endif
