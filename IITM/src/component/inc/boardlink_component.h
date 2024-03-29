#ifndef __BOARDLINK_COMPONENT__
#define __BOARDLINK_COMPONENT__

#include "simple_i2c_component.h"

/******************************** MACRO DEFINITIONS ********************************/
// Last byte of the component ID is the I2C address
#define COMPONENT_ADDR_MASK 0x000000FF             
#define I2C_POLL_LIMIT 10000 //random number

/******************************** FUNCTION PROTOTYPES ********************************/

int board_link_init(uint32_t component_id);

int send_packet_and_ack(buf_u8 packet);
int wait_and_receive_packet_with_poll_limit(buf_u8 packet);
int wait_and_receive_packet(buf_u8 packet);

#endif
