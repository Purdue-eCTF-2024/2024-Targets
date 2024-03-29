#ifndef __I2C_SIMPLE_COMPONENT__
#define __I2C_SIMPLE_COMPONENT__

#include "i2c_reva_regs.h"
#include "i2c_reva.h"
#include "stdbool.h"
#include "stdint.h"
#include "mxc_errors.h"
#include "board.h"
#include "nvic_table.h"
#include "i2c.h"

//custom packages
#include "secure_buffer.h"
#include "i2c_defs.h"
#include <stdint.h>


/******************************** EXTERN DEFINITIONS ********************************/
// Extern definition to make I2C_REGS and I2C_REGS_LEN 
// accessible outside of the implementation
extern volatile buf_u8 I2C_REGS[7];

/******************************** FUNCTION PROTOTYPES ********************************/
int i2c_simple_peripheral_init(i2c_addr_t addr);
void i2c_simple_peripheral_destory(void);

#endif
