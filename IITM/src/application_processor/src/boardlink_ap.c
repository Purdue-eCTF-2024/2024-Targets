#include <stdint.h>
#include <string.h>

#include "boardlink_ap.h"
#include "mxc_delay.h"
#include "secure_host_messaging.h"
#include "simple_i2c_ap.h"

void board_link_init(void) {
    i2c_simple_ap_init();
}

int check_component_liveness(uint32_t component_id) {
    i2c_addr_t address = component_id_to_i2c_addr(component_id);
    INIT_BUF_U8(ready_buf, 1);
    int result;
    for (int i = 0; i < 50; i++) {
        result = i2c_simple_read_ready(address, ready_buf);
    }
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    return SUCCESS_RETURN;
}

int send_packet_and_ack(uint32_t component_id, buf_u8 packet) {
    i2c_addr_t address = component_id_to_i2c_addr(component_id);
    int result;
    uint8_t len = packet.size;
    INIT_BUF_U8(ready_buf, 1);
    set_u8(ready_buf, 0, false);
    bool ready_flag = false;
    // for(int i = 0; i<10 ;i++)
    // {
    //     result = i2c_simple_read_ready(address, ready_buf);
    //     MXC_Delay(50);
    // }
    // if (result == ERROR_RETURN) {
    //     return ERROR_RETURN;
    // }
    // else if(access_u8(ready_buf, 0))
    // {
    //     ready_flag = true;
    // }
    // else {
    //     for (int i = 0; i < I2C_READY_POLL_LIMIT; i++) {
    //     result = i2c_simple_read_ready(address, ready_buf);
    //     MXC_Delay(50);
    //     if (result == ERROR_RETURN) {
    //         return ERROR_RETURN;
    //     } else if (access_u8(ready_buf, 0)) {
    //         ready_flag = true;
    //         break;
    //     }
    // }
    // }
    for (int i = 0; i < I2C_READY_POLL_LIMIT; i++) {
        result = i2c_simple_read_ready(address, ready_buf);
        if (result == ERROR_RETURN) {
            return ERROR_RETURN;
        } else if (access_u8(ready_buf, 0)) {
            ready_flag = true;
            break;
        }
    }
    if (!ready_flag) {
        panic();
        return ERROR_RETURN;
    }
    result = i2c_simple_write_receive_len(address, len);
    if (result != SUCCESS_RETURN) {
        panic();
        return ERROR_RETURN;
    }
    result = i2c_simple_write_data_generic(address, RECEIVE, packet);
    if (result != SUCCESS_RETURN) {
        panic();
        return ERROR_RETURN;
    }
    result = i2c_simple_write_receive_done(address, true);
    if (result != SUCCESS_RETURN) {
        panic();
        return ERROR_RETURN;
    }
    INIT_BUF_U8(receive_done_buf, 1);
    for (int i = 0; i < I2C_POLL_LIMIT; i++) {
        result = i2c_simple_read_receive_done(address, receive_done_buf);
        if (result == ERROR_RETURN) {
            panic();
            continue;
        } else if (!access_u8(receive_done_buf, 0)) {
            return SUCCESS_RETURN;
        }
    }
    panic();
    return ERROR_RETURN;
}

int poll_and_receive_packet(uint32_t component_id, buf_u8 packet) {

    i2c_addr_t address = component_id_to_i2c_addr(component_id);
    int result = SUCCESS_RETURN;
    INIT_BUF_U8(transmit_done_buf, 1);
    bool ready = false;
    for (int i = 0; i < I2C_POLL_LIMIT; i++) {
        result = i2c_simple_read_transmit_done(address, transmit_done_buf);
        if (result != ERROR_RETURN &&
            access_u8(transmit_done_buf, 0) == false) {
            ready = true;
            break;
        }
    }
    if (!ready) {
        panic();
        return ERROR_RETURN;
    }
    INIT_BUF_U8(transmit_len_buf, 1);
    result = i2c_simple_read_transmit_len(address, transmit_len_buf);
    if (result != SUCCESS_RETURN) {
        panic();
        return ERROR_RETURN;
    }
    uint8_t transmit_len = access_u8(transmit_len_buf, 0);
    assert_min_size_bu8(packet, transmit_len);
    result =
        i2c_simple_read_data_generic(address, TRANSMIT, transmit_len, packet);
    if (result != SUCCESS_RETURN) {
        panic();
        return ERROR_RETURN;
    }
    result = i2c_simple_write_transmit_done(address, true);
    if (result != SUCCESS_RETURN) {
        panic();
        return ERROR_RETURN;
    }
    return (int)transmit_len;
}
