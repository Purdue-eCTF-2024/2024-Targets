#include <stdint.h>
#include <string.h>

#include "boardlink_component.h"
#include "helper_functions.h"
#include "secure_host_messaging.h"

int board_link_init(uint32_t component_id) {
    i2c_addr_t address = component_id_to_i2c_addr(component_id);
    return i2c_simple_peripheral_init(address);
}

int send_packet_and_ack(buf_u8 packet) {
    uint32_t len = packet.size;
    if (len + 1 > MAX_I2C_MESSAGE_LEN)
        panic();
    set_u8(I2C_REGS[TRANSMIT_LEN], 0, (uint8_t)len);
    cpy_bu8(I2C_REGS[TRANSMIT], packet, len);
    set_u8(I2C_REGS[TRANSMIT_DONE], 0, false);

    // Wait for ack from AP
    while (!access_u8(I2C_REGS[TRANSMIT_DONE], 0)) {}
    return SUCCESS_RETURN;

}

int wait_and_receive_packet_with_poll_limit(buf_u8 packet) {
    set_u8(I2C_REGS[READY], 0, true);
    for (int i = 0; i < I2C_POLL_LIMIT; i++) {
        if (access_u8(I2C_REGS[RECEIVE_DONE], 0)) {
            set_u8(I2C_REGS[READY], 0, false);
            uint8_t len = access_u8(I2C_REGS[RECEIVE_LEN], 0);
            cpy_bu8(packet, I2C_REGS[RECEIVE], len);
            set_u8(I2C_REGS[RECEIVE_DONE], 0, false);
            spin();
            return (int)len;
        }
    }
    panic();
    return ERROR_RETURN;
}

int wait_and_receive_packet(buf_u8 packet) {
    set_u8(I2C_REGS[READY], 0, true);
    while (true) {
        if (access_u8(I2C_REGS[RECEIVE_DONE], 0)) {
            set_u8(I2C_REGS[READY], 0, false);
            uint8_t len = access_u8(I2C_REGS[RECEIVE_LEN], 0);
            cpy_bu8(packet, I2C_REGS[RECEIVE], len);
            set_u8(I2C_REGS[RECEIVE_DONE], 0, false);
            spin();
            return (int)len;
        }
    }
}
