#ifndef __BOARDLINK_AP__
#define __BOARDLINK_AP__

#include "simple_i2c_ap.h"

/******************************** MACRO DEFINITIONS ********************************/
#define I2C_POLL_LIMIT 1000 //random number
#define I2C_READY_POLL_LIMIT 1000 //random number

/******************************** FUNCTION PROTOTYPES ********************************/

void board_link_init(void);
int check_component_liveness(uint32_t component_id);
int send_packet_and_ack(uint32_t component_id, buf_u8 packet);
int poll_and_receive_packet(uint32_t component_id, buf_u8 packet);

#endif
