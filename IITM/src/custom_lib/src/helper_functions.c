#include "helper_functions.h"
#include "cmsis_gcc.h"
#include "mxc_delay.h"
#include "secure_buffer.h"
#include "secure_host_messaging.h"
#include "trng.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "mxc_sys.h"
#include "simple_flash.h"
#ifndef AP
#include "simple_i2c_component.h"
#endif

void init_rng() {
    MXC_TRNG_Init();
}

uint32_t rand_uint() {
    return MXC_TRNG_RandomInt();
}

void switch_internal_clock(void) {
    MXC_SYS_ClockSourceEnable(MXC_SYS_CLOCK_IPO);
    MXC_SYS_Clock_Select(MXC_SYS_CLOCK_IPO);
}

void disable_extra() {
    //disable clock to the riscv co processor
    MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_CPU1);
    // disable clock to spi communications
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_SPI1);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_SPI0);
    // //disabled all other peripherals
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_DMA);
    // // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_TMR0);
    // // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_TMR1);
    // // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_TMR2);
    // // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_TMR3);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_ADC);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_CNN);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_PT);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_SMPHR);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_OWIRE);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_CRC);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_AES);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_I2S);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_PCIF);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_WDT0);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_WDT1);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_TMR4);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_TMR5);
    // MXC_SYS_ClockDisable(MXC_SYS_PERIPH_CLOCK_LPCOMP);


}

static void branch_to_reset() {
    __asm(
    "   ldr     r0, =Reset_Handler\n"
    "   blx     r0\n"
    );
}

void panic() {
#ifdef AP
    flash_entry_ap_t flash_status_panic;
    flash_simple_read(FLASH_ADDR, (uint32_t *)&flash_status_panic,
                      sizeof(flash_entry_ap_t));

    flash_status_panic.state = STATE_PANIC;
    flash_simple_erase_page(FLASH_ADDR);
    flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status_panic,
                       sizeof(flash_entry_ap_t));
#else  // ndef AP
    i2c_simple_peripheral_destory();
    flash_entry_component_t flash_status_panic;
    flash_simple_read(FLASH_ADDR, (uint32_t *)&flash_status_panic,
                      sizeof(flash_entry_component_t));
    flash_status_panic.state = STATE_PANIC;
    flash_simple_erase_page(FLASH_ADDR);
    flash_simple_write(FLASH_ADDR, (uint32_t *)&flash_status_panic,
                       sizeof(flash_entry_component_t));
#endif // AP
    print_error("Panic, please power cycle or press the reset button\n");
    spin();
    MXC_Delay(50000);
    branch_to_reset();
}


uint8_t verify_string(const char *str, uint32_t len) {
    // Checks if the string is doesnt contain any format specifiers
    for (int i = 0; i < len; i++) {
        if (str[i] == '%' && str[i + 1] != '%') {
            return 0;
        }
    }
    return 1;
}

void spin() {
    volatile int random_number = rand_uint();
    volatile int r2 = random_number;
    random_number = random_number & 0x7FF;
    volatile int counter = 0;
    for (int i = 0; i < random_number; i++) {
        counter = counter * 42069;
        counter = counter % 69420;
        switch (r2 % 3) {
        case 0:
            // ADD_HERE_NOP
            break;
        case 1:
            // ADD_HERE_NOP
            break;
        case 2:
            // ADD_HERE_NOP
            break;
        }
        MXC_Delay(r2 & 0xF);
        r2 = (6991 * r2 + 69911) % 69991;
    }
}

void SysCtlDelay(uint32_t ui32Count) {
    __asm("    subs    r0, #1\n"
          "    bne.n   SysCtlDelay\n"
          "    bx      lr");
}
