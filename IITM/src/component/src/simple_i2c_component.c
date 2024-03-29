#include "simple_i2c_component.h"
#include "i2c_defs.h"
#include "secure_buffer.h"
#include <stdint.h>

/******************************** GLOBAL DEFINITIONS
 * ********************************/
// Data for all of the I2C registers
INIT_VOL_BUF_U8(RECEIVE_REG, MAX_I2C_MESSAGE_LEN);
INIT_VOL_BUF_U8(RECEIVE_DONE_REG, 1);
INIT_VOL_BUF_U8(RECEIVE_LEN_REG, 1);
INIT_VOL_BUF_U8(TRANSMIT_REG, MAX_I2C_MESSAGE_LEN);
INIT_VOL_BUF_U8(TRANSMIT_DONE_REG, 1);
INIT_VOL_BUF_U8(TRANSMIT_LEN_REG, 1);
INIT_VOL_BUF_U8(READY_REG, 1);

// Data structure to allow easy reference of I2C registers
volatile buf_u8 I2C_REGS[7];

/******************************** FUNCTION PROTOTYPES
 * ********************************/
static void i2c_simple_isr(void);

int i2c_simple_peripheral_init(uint8_t addr) {
    I2C_REGS[RECEIVE] = RECEIVE_REG;
    I2C_REGS[RECEIVE_DONE] = RECEIVE_DONE_REG;
    I2C_REGS[RECEIVE_LEN] = RECEIVE_LEN_REG;
    I2C_REGS[TRANSMIT] = TRANSMIT_REG;
    I2C_REGS[TRANSMIT_DONE] = TRANSMIT_DONE_REG;
    I2C_REGS[TRANSMIT_LEN] = TRANSMIT_LEN_REG;
    I2C_REGS[READY] = READY_REG;

    int error;
    // Initialize the I2C Interface
    error = MXC_I2C_Init(I2C_INTERFACE, false, addr);
    if (error != E_NO_ERROR) {
        panic();
        return error;
    }

    // Set frequency and clear FIFO
    MXC_I2C_SetFrequency(I2C_INTERFACE, I2C_FREQ);
    // Set timeout for component's clock stretching
    MXC_I2C_SetTimeout(I2C_INTERFACE, I2C_TIMEOUT_LIMIT);
    MXC_I2C_ClearRXFIFO(I2C_INTERFACE);

    // Enable interrupts and link ISR
    MXC_I2C_EnableInt(I2C_INTERFACE, MXC_F_I2C_INTFL0_RD_ADDR_MATCH, 0);
    MXC_I2C_EnableInt(I2C_INTERFACE, MXC_F_I2C_INTFL0_WR_ADDR_MATCH, 0);
    MXC_I2C_EnableInt(I2C_INTERFACE, MXC_F_I2C_INTFL0_STOP, 0);
    MXC_NVIC_SetVector(MXC_I2C_GET_IRQ(MXC_I2C_GET_IDX(I2C_INTERFACE)),
                       i2c_simple_isr);
    NVIC_EnableIRQ(MXC_I2C_GET_IRQ(MXC_I2C_GET_IDX(I2C_INTERFACE)));
    MXC_I2C_ClearFlags(I2C_INTERFACE, 0xFFFFFFFF, 0xFFFFFFFF);

    // Prefix READY values for registers
    set_u8(I2C_REGS[RECEIVE_DONE], 0, false);
    set_u8(I2C_REGS[READY], 0, false);
    set_u8(I2C_REGS[TRANSMIT_DONE], 0, true);

    return E_NO_ERROR;
}

void i2c_simple_peripheral_destory(void) {
    NVIC_DisableIRQ(MXC_I2C_GET_IRQ(MXC_I2C_GET_IDX(I2C_INTERFACE)));
    // MXC_I2C_DisableInt(I2C_INTERFACE, 0xFFFFFFFF, 0xFFFFFFFF);
    // MXC_I2C_Disable(I2C_INTERFACE);
}
// Main program flow, ISR
void i2c_simple_isr(void) {
    // Variables for state of ISR
    static bool WRITE_START = false;
    static int READ_INDEX = 0;
    static int WRITE_INDEX = 0;
    static ECTF_I2C_REGS ACTIVE_REG = RECEIVE;

    // Read interrupt flags
    uint32_t Flags = I2C_INTERFACE->intfl0;

    // Transaction over interrupt
    if (Flags & MXC_F_I2C_INTFL0_STOP) {

        // Ready any remaining data
        if (WRITE_START == true) {
            MXC_I2C_ReadRXFIFO(I2C_INTERFACE, (volatile uint8_t *)&ACTIVE_REG,
                               1);
            WRITE_START = false;
        }
        if (ACTIVE_REG <= MAX_REG) {
            uint32_t available = MXC_I2C_GetRXFIFOAvailable(I2C_INTERFACE);
            buf_u8 write_slice = slice_bu8(I2C_REGS[ACTIVE_REG], WRITE_INDEX,
                                           I2C_REGS[ACTIVE_REG].size);
            if (available <= write_slice.size) {
                WRITE_INDEX += MXC_I2C_ReadRXFIFO(
                    I2C_INTERFACE, (volatile uint8_t *)(write_slice.data),
                    available);
            }
        } else {
            panic();
            // return;
            MXC_I2C_ClearRXFIFO(I2C_INTERFACE);
        }

        // Disable bulk send/receive inter\rupts
        MXC_I2C_DisableInt(I2C_INTERFACE, MXC_F_I2C_INTEN0_RX_THD, 0);
        MXC_I2C_DisableInt(I2C_INTERFACE, MXC_F_I2C_INTEN0_TX_THD, 0);

        // Clear FIFOs if full
        if (MXC_I2C_GetRXFIFOAvailable(I2C_INTERFACE) != 0) {
            MXC_I2C_ClearRXFIFO(I2C_INTERFACE);
        }
        if (MXC_I2C_GetTXFIFOAvailable(I2C_INTERFACE) != 8) {
            MXC_I2C_ClearTXFIFO(I2C_INTERFACE);
        }

        // Reset state
        READ_INDEX = 0;
        WRITE_INDEX = 0;
        WRITE_START = false;

        // Clear ISR flag
        MXC_I2C_ClearFlags(I2C_INTERFACE, MXC_F_I2C_INTFL0_STOP, 0);
    }

    // TX Fifo Threshold Met on Read
    if (Flags & MXC_F_I2C_INTEN0_TX_THD &&
        (I2C_INTERFACE->inten0 & MXC_F_I2C_INTEN0_TX_THD)) {

        if (Flags & MXC_F_I2C_INTFL0_TX_LOCKOUT) {
            MXC_I2C_ClearFlags(I2C_INTERFACE, MXC_F_I2C_INTFL0_TX_LOCKOUT, 0);
        }
        // 2 bytes in TX fifo triggers threshold by default
        // 8 byte FIFO length by default
        // More data is needed within the FIFO
        if (ACTIVE_REG <= MAX_REG) {
            buf_u8 remaining_slice = slice_bu8(I2C_REGS[ACTIVE_REG], READ_INDEX,
                                               I2C_REGS[ACTIVE_REG].size);
            READ_INDEX += MXC_I2C_WriteTXFIFO(
                I2C_INTERFACE, (volatile uint8_t *)(remaining_slice.data),
                remaining_slice.size);

            if (I2C_REGS[ACTIVE_REG].size - 1 == READ_INDEX) {
                MXC_I2C_DisableInt(I2C_INTERFACE, MXC_F_I2C_INTEN0_TX_THD, 0);
            }
        }

        // Clear ISR flag
        MXC_I2C_ClearFlags(I2C_INTERFACE, MXC_F_I2C_INTFL0_TX_THD, 0);
    }

    // Read from Peripheral from Controller Match
    if (Flags & MXC_F_I2C_INTFL0_WR_ADDR_MATCH) {
        // Clear ISR flag
        MXC_I2C_ClearFlags(I2C_INTERFACE, MXC_F_I2C_INTFL0_WR_ADDR_MATCH, 0);

        // TX_LOCKOUT Triggers at the start of a just-in-time read
        if (Flags & MXC_F_I2C_INTFL0_TX_LOCKOUT) {
            MXC_I2C_ClearFlags(I2C_INTERFACE, MXC_F_I2C_INTFL0_TX_LOCKOUT, 0);

            // Select active register
            MXC_I2C_ReadRXFIFO(I2C_INTERFACE, (volatile uint8_t *)&ACTIVE_REG,
                               1);

            // Write data to TX Buf
            if (ACTIVE_REG <= MAX_REG) {
                buf_u8 remaining_slice =
                    slice_bu8(I2C_REGS[ACTIVE_REG], READ_INDEX,
                              I2C_REGS[ACTIVE_REG].size);
                READ_INDEX += MXC_I2C_WriteTXFIFO(
                    I2C_INTERFACE, (volatile uint8_t *)(remaining_slice.data),
                    remaining_slice.size);

                if (READ_INDEX < remaining_slice.size) {
                    MXC_I2C_EnableInt(I2C_INTERFACE, MXC_F_I2C_INTEN0_TX_THD,
                                      0);
                }
            }
        }
    }

    // Write to Peripheral from Controller Match
    if (Flags & MXC_F_I2C_INTFL0_RD_ADDR_MATCH) {
        // Set write start variable
        WRITE_START = true;

        // Enable bulk receive interrupt
        MXC_I2C_EnableInt(I2C_INTERFACE, MXC_F_I2C_INTEN0_RX_THD, 0);

        // Clear flag
        MXC_I2C_ClearFlags(I2C_INTERFACE, MXC_F_I2C_INTFL0_RD_ADDR_MATCH, 0);
    }

    // RX Fifo Threshold Met on Write
    if (Flags & MXC_F_I2C_INTEN0_RX_THD) {
        // We always write a register before writing data so select register
        if (WRITE_START == true) {
            MXC_I2C_ReadRXFIFO(I2C_INTERFACE,
                               (volatile unsigned char *)&ACTIVE_REG, 1);
            WRITE_START = false;
        }
        // Read remaining data
        if (ACTIVE_REG <= MAX_REG) {
            int available = MXC_I2C_GetRXFIFOAvailable(I2C_INTERFACE);
            if (available < (I2C_REGS[ACTIVE_REG].size - WRITE_INDEX)) {
                WRITE_INDEX += MXC_I2C_ReadRXFIFO(
                    I2C_INTERFACE, &I2C_REGS[ACTIVE_REG].data[WRITE_INDEX],
                    MXC_I2C_GetRXFIFOAvailable(I2C_INTERFACE));
            } else {
                WRITE_INDEX += MXC_I2C_ReadRXFIFO(
                    I2C_INTERFACE, &I2C_REGS[ACTIVE_REG].data[WRITE_INDEX],
                    I2C_REGS[ACTIVE_REG].size - WRITE_INDEX);
            }
            // Clear out FIFO if invalid register specified
        } else {
            MXC_I2C_ClearRXFIFO(I2C_INTERFACE);
        }

        // Clear ISR flag
        MXC_I2C_ClearFlags(I2C_INTERFACE, MXC_F_I2C_INTFL0_RX_THD, 0);
    }
}
