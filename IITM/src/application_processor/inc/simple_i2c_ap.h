#ifndef __I2C_SIMPLE_AP__
#define __I2C_SIMPLE_AP__

#include "stdbool.h"
#include "stdint.h"
#include "mxc_errors.h"
#include "board.h"
#include "nvic_table.h"
#include "i2c.h"
#include "string.h"

//custom packages
#include "secure_buffer.h"
#include "i2c_defs.h"

int i2c_simple_ap_init(void);

int i2c_simple_read_receive_done(i2c_addr_t addr, buf_u8 value_buf);
int i2c_simple_read_receive_len(i2c_addr_t addr, buf_u8 value_buf);
int i2c_simple_read_transmit_done(i2c_addr_t addr, buf_u8 value_buf);
int i2c_simple_read_transmit_len(i2c_addr_t addr, buf_u8 value_buf);
int i2c_simple_read_ready(i2c_addr_t addr, buf_u8 value_buf);
int i2c_simple_read_send_ack(i2c_addr_t addr, buf_u8 value_buf);
int i2c_simple_write_send_ack(i2c_addr_t addr, bool done);
int i2c_simple_write_receive_done(i2c_addr_t addr, bool done);
int i2c_simple_write_receive_len(i2c_addr_t addr, uint8_t len);
int i2c_simple_write_transmit_done(i2c_addr_t addr, bool done);
int i2c_simple_write_transmit_len(i2c_addr_t addr, uint8_t len);

int i2c_simple_read_data_generic(i2c_addr_t addr, ECTF_I2C_REGS reg, uint8_t len, buf_u8 buf);
int i2c_simple_write_data_generic(i2c_addr_t addr, ECTF_I2C_REGS reg, buf_u8 buf);
int i2c_simple_read_status_generic(i2c_addr_t addr, ECTF_I2C_REGS reg, buf_u8 value_buf);
int i2c_simple_write_status_generic(i2c_addr_t addr, ECTF_I2C_REGS reg, uint8_t value);

#endif
