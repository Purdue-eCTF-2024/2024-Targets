#include "i2c_defs.h"

i2c_addr_t component_id_to_i2c_addr(uint32_t component_id) {
    return component_id & COMPONENT_ADDR_MASK;
}
