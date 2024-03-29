#ifndef I2C_DEFS_H_
#define I2C_DEFS_H_

#include "stdint.h"

#define I2C_FREQ 100000
#define I2C_INTERFACE MXC_I2C1
#define MAX_I2C_MESSAGE_LEN 255
#define I2C_TIMEOUT_LIMIT 100000
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

// Last byte of the component ID is the I2C address
#define COMPONENT_ADDR_MASK 0x000000FF

/**
 * Enumeration with registers on the peripheral device.
 */
typedef enum {
    /**
    * Buffer for receiving data.
    */
    RECEIVE,
    /**
     * ACK for receiving data.
     */
    RECEIVE_DONE,
    /**
     * Length of data being received.
     */
    RECEIVE_LEN,
    /**
     * Buffer for tramsitting data.
     */
    TRANSMIT,
    /**
     * ACK for transmitting data.
     */
    TRANSMIT_DONE,
    /**
     * Length of data being transitted.
     */
    TRANSMIT_LEN,
    /**
     * Indicates that a component is listening.
     */
    READY,
    /**
     * Unused.
     */
    SEND_ACK
} ECTF_I2C_REGS;
#define MAX_REG SEND_ACK

typedef uint8_t i2c_addr_t;

/**
 * Translate 32-bit component ID to an I2C ID.
 */
i2c_addr_t component_id_to_i2c_addr(uint32_t component_id);

#endif // I2C_DEFS_H_
