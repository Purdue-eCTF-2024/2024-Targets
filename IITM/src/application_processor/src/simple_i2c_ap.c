#include "simple_i2c_ap.h"
#include "helper_functions.h"
#include "i2c_defs.h"
#include "mxc_delay.h"

/******************************** FUNCTION PROTOTYPES
 * ********************************/
static void I2C_Handler(void) {
    MXC_I2C_AsyncHandler(I2C_INTERFACE);
}

/******************************** FUNCTION DEFINITIONS
 * ********************************/
int i2c_simple_ap_init(void) {
    int error;

    // Initialize the I2C Interface
    error = MXC_I2C_Init(I2C_INTERFACE, true, 0);
    if (error != E_NO_ERROR) {
        panic();
        return error;
    }
    // Set frequency to frequency macro
    MXC_I2C_SetFrequency(I2C_INTERFACE, I2C_FREQ);

    // setting timeout for i2c
    MXC_I2C_SetTimeout(I2C_INTERFACE, I2C_TIMEOUT_LIMIT);

    // Set up interrupt
    MXC_NVIC_SetVector(MXC_I2C_GET_IRQ(MXC_I2C_GET_IDX(I2C_INTERFACE)),
                       I2C_Handler);
    NVIC_EnableIRQ(MXC_I2C_GET_IRQ(MXC_I2C_GET_IDX(I2C_INTERFACE)));

    return E_NO_ERROR;
}

int i2c_simple_read_receive_done(i2c_addr_t addr, buf_u8 value_buf) {
    return i2c_simple_read_status_generic(addr, RECEIVE_DONE, value_buf);
}

int i2c_simple_read_receive_len(i2c_addr_t addr, buf_u8 value_buf) {
    return i2c_simple_read_status_generic(addr, RECEIVE_LEN, value_buf);
}

int i2c_simple_read_transmit_done(i2c_addr_t addr, buf_u8 value_buf) {
    return i2c_simple_read_status_generic(addr, TRANSMIT_DONE, value_buf);
}

int i2c_simple_read_transmit_len(i2c_addr_t addr, buf_u8 value_buf) {
    return i2c_simple_read_status_generic(addr, TRANSMIT_LEN, value_buf);
}

int i2c_simple_read_ready(i2c_addr_t addr, buf_u8 value_buf) {
    return i2c_simple_read_status_generic(addr, READY, value_buf);
}

int i2c_simple_read_send_ack(i2c_addr_t addr, buf_u8 value_buf) {
    return i2c_simple_read_status_generic(addr, SEND_ACK, value_buf);
}

int i2c_simple_write_send_ack(i2c_addr_t addr, bool done) {
    return i2c_simple_write_status_generic(addr, SEND_ACK, done);
}

int i2c_simple_write_receive_done(i2c_addr_t addr, bool done) {
    return i2c_simple_write_status_generic(addr, RECEIVE_DONE, done);
}

int i2c_simple_write_receive_len(i2c_addr_t addr, uint8_t len) {
    return i2c_simple_write_status_generic(addr, RECEIVE_LEN, len);
}

int i2c_simple_write_transmit_done(i2c_addr_t addr, bool done) {
    return i2c_simple_write_status_generic(addr, TRANSMIT_DONE, done);
}

int i2c_simple_write_transmit_len(i2c_addr_t addr, uint8_t len) {
    return i2c_simple_write_status_generic(addr, TRANSMIT_LEN, len);
}

int i2c_simple_read_data_generic(i2c_addr_t addr, ECTF_I2C_REGS reg,
                                 uint8_t len, buf_u8 buf) {
    if (len > MAX_I2C_MESSAGE_LEN)
        panic();
    if (len > buf.size)
        panic();
    mxc_i2c_req_t request;
    request.i2c = I2C_INTERFACE;
    request.addr = addr;
    request.tx_len = 1;
    request.tx_buf = (uint8_t *)&reg;
    request.rx_len = len;
    request.rx_buf = buf.data;
    request.restart = 0;
    request.callback = NULL;

    int result = MXC_I2C_MasterTransaction(&request);
    if (result == 0)
        return SUCCESS_RETURN;
    else
        return ERROR_RETURN;
}

int i2c_simple_write_data_generic(i2c_addr_t addr, ECTF_I2C_REGS reg,
                                  buf_u8 buf) {
    uint32_t len = buf.size;
    if (len + 1 > MAX_I2C_MESSAGE_LEN)
        panic();
    INIT_BUF_U8(packet, buf.size + 1);
    set_u8(packet, 0, (uint8_t)reg);
    for (int i = 0; i < buf.size; i++) {
        set_u8(packet, i + 1, access_u8(buf, i));
    }

    mxc_i2c_req_t request;
    request.i2c = I2C_INTERFACE;
    request.addr = addr;
    request.tx_len = len + 1;
    request.tx_buf = packet.data;
    request.rx_len = 0;
    request.rx_buf = 0;
    request.restart = 0;
    request.callback = NULL;

    int result = MXC_I2C_MasterTransaction(&request);
    MXC_Delay(2000);
    if (result == 0)
        return SUCCESS_RETURN;
    else
        return ERROR_RETURN;
}

int i2c_simple_read_status_generic(i2c_addr_t addr, ECTF_I2C_REGS reg,
                                   buf_u8 value_buf) {
    if (value_buf.size != 1) {
        panic();
    }
    mxc_i2c_req_t request;
    request.i2c = I2C_INTERFACE;
    request.addr = addr;
    request.tx_len = 1;
    request.tx_buf = (uint8_t *)&reg;
    request.rx_len = 1;
    request.rx_buf = value_buf.data;
    request.restart = 0;
    request.callback = NULL;

    int result = MXC_I2C_MasterTransaction(&request);
    if (result != 0) {
        return ERROR_RETURN;
    } else {
        return SUCCESS_RETURN;
    }
    MXC_Delay(2000);
}

int i2c_simple_write_status_generic(i2c_addr_t addr, ECTF_I2C_REGS reg,
                                    uint8_t value) {
    uint8_t packet[2];
    packet[0] = (uint8_t)reg;
    packet[1] = value;

    mxc_i2c_req_t request;
    request.i2c = I2C_INTERFACE;
    request.addr = addr;
    request.tx_len = 2;
    request.tx_buf = packet;
    request.rx_len = 0;
    request.rx_buf = 0;
    request.restart = 0;
    request.callback = NULL;

    int result = MXC_I2C_MasterTransaction(&request);
    MXC_Delay(2000);
    if (result == 0)
        return SUCCESS_RETURN;
    else
        return ERROR_RETURN;
}
