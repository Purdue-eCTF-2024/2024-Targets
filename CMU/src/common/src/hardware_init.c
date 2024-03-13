/**
 * @file hardware_init.c
 * @author Plaid Parliament of Pwning
 * @brief Hardware initialization functions
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include "hardware_init.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gcr_regs.h"
#include "gpio.h"
#include "icc_regs.h"
#include "lpgcr_regs.h"
#include "max78000.h"
#include "mxc_delay.h"
#include "uart.h"
#include "util.h"  // For UTIL_ASSERT

// For CONSOLE_UART and CONSOLE_BAUD
#if IS_AP
#include "host_uart.h"
#endif  // IS_AP

static void disable_irq(void);
static void disable_cache(void);
static void disable_clocks(void);
static void disable_events(void);

static void set_vtor(void);
static void update_system_core_clock(void);

static void init_gpio_clocks(void);
static void init_uart(void);
static void init_led(void);

extern void (*const __isr_vector[])(void);
uint32_t SystemCoreClock __attribute__((section(".shared")));

/**
 * @brief Initializes required hardware peripherals
 */
void hardware_init(void) {
    // Disable unused functionalities
    disable_irq();
    disable_cache();
    disable_clocks();
    disable_events();

    // Setup originally done in SystemInit
    set_vtor();
    update_system_core_clock();

    // Setup originally done in Board_Init
    init_gpio_clocks();
    init_uart();
    init_led();

    // Wait for PMIC 1.8V to become available, about 180ms after power up
    // (originally done in Board_Init)
    MXC_Delay(200000);
}

/**
 * @brief Disables interrupts globally and on NVIC
 */
static void disable_irq(void) {
    // Mask interrupts globally (Reset, NMI, and HardFault are NOT maskable)
    __disable_irq();

    // Disable all interrupts that can be disabled
    for (IRQn_Type irq = 0; irq < MXC_IRQ_EXT_COUNT; irq++) {
        NVIC_DisableIRQ(irq);  // irq MUST NOT be negative
    }
}

/**
 * @brief Disables the instruction cache
 */
static void disable_cache(void) {
    // Disable all ICCs
    MXC_ICC0->ctrl &= ~MXC_F_ICC_CTRL_EN;
    MXC_ICC1->ctrl &= ~MXC_F_ICC_CTRL_EN;
}

/**
 * @brief Disables other clocks 
 */
static void disable_clocks(void) {
    // Disable regular peripheral clocks
    MXC_GCR->pclkdis0 |= MXC_F_GCR_PCLKDIS0_GPIO0 | MXC_F_GCR_PCLKDIS0_GPIO1 |
                         MXC_F_GCR_PCLKDIS0_DMA | MXC_F_GCR_PCLKDIS0_SPI1 |
                         MXC_F_GCR_PCLKDIS0_UART0 | MXC_F_GCR_PCLKDIS0_UART1 |
                         MXC_F_GCR_PCLKDIS0_I2C0 | MXC_F_GCR_PCLKDIS0_TMR0 |
                         MXC_F_GCR_PCLKDIS0_TMR1 | MXC_F_GCR_PCLKDIS0_TMR2 |
                         MXC_F_GCR_PCLKDIS0_TMR3 | MXC_F_GCR_PCLKDIS0_ADC |
                         MXC_F_GCR_PCLKDIS0_CNN | MXC_F_GCR_PCLKDIS0_I2C1 |
                         MXC_F_GCR_PCLKDIS0_PT;
    MXC_GCR->pclkdis1 |= MXC_F_GCR_PCLKDIS1_UART2 | MXC_F_GCR_PCLKDIS1_TRNG |
                         MXC_F_GCR_PCLKDIS1_SMPHR | MXC_F_GCR_PCLKDIS1_OWM |
                         MXC_F_GCR_PCLKDIS1_CRC | MXC_F_GCR_PCLKDIS1_AES |
                         MXC_F_GCR_PCLKDIS1_SPI0 | MXC_F_GCR_PCLKDIS1_PCIF |
                         MXC_F_GCR_PCLKDIS1_I2S | MXC_F_GCR_PCLKDIS1_I2C2 |
                         MXC_F_GCR_PCLKDIS1_WDT0 | MXC_F_GCR_PCLKDIS1_CPU1;

    // Disable low-power peripheral clocks
    MXC_LPGCR->pclkdis |= MXC_F_LPGCR_PCLKDIS_GPIO2 | MXC_F_LPGCR_PCLKDIS_WDT1 |
                          MXC_F_LPGCR_PCLKDIS_TMR4 | MXC_F_LPGCR_PCLKDIS_TMR5 |
                          MXC_F_LPGCR_PCLKDIS_UART3 |
                          MXC_F_LPGCR_PCLKDIS_LPCOMP;
}

/**
 * @brief Disables events
 */
static void disable_events(void) {
    // Disable all events
    MXC_GCR->eventen &= ~(MXC_F_GCR_EVENTEN_DMA | MXC_F_GCR_EVENTEN_TX);
}

/**
 * @brief Set the vtor object
 */
static void set_vtor(void) {
    // Configure the interrupt controller to use the application vector table in
    // the application space
#if defined(__CC_ARM) || defined(__GNUC__)
    // IAR sets the VTOR pointer incorrectly and causes stack corruption
    SCB->VTOR = (uint32_t)__isr_vector;
#endif  // defined(__CC_ARM) || defined(__GNUC__)
}

/**
 * @brief Updates the system core clock
 */
static void update_system_core_clock(void) {
    uint32_t base_freq = HIRC_FREQ;  // Initial value doesn't matter

    // Get the clock source and frequency
    const uint32_t clk_src = (MXC_GCR->clkctrl & MXC_F_GCR_CLKCTRL_SYSCLK_SEL);
    switch (clk_src) {
        case MXC_S_GCR_CLKCTRL_SYSCLK_SEL_EXTCLK:
            base_freq = EXTCLK_FREQ;
            break;
        case MXC_S_GCR_CLKCTRL_SYSCLK_SEL_INRO:
            base_freq = INRO_FREQ;
            break;
        case MXC_S_GCR_CLKCTRL_SYSCLK_SEL_IPO:
            base_freq = IPO_FREQ;
            break;
        case MXC_S_GCR_CLKCTRL_SYSCLK_SEL_IBRO:
            base_freq = IBRO_FREQ;
            break;
        case MXC_S_GCR_CLKCTRL_SYSCLK_SEL_ISO:
            base_freq = ISO_FREQ;
            break;
        case MXC_S_GCR_CLKCTRL_SYSCLK_SEL_ERTCO:
            base_freq = ERTCO_FREQ;
            break;
        default:
            // Codes 001 and 111 are reserved.
            // This code should never execute, however, initialize to safe
            // value.
            base_freq = HIRC_FREQ;
            break;
    }

    const uint32_t div = (MXC_GCR->clkctrl & MXC_F_GCR_CLKCTRL_SYSCLK_DIV) >>
                         MXC_F_GCR_CLKCTRL_SYSCLK_DIV_POS;

    SystemCoreClock = base_freq >> div;
}

/**
 * @brief Initialize GPIO clocks
 */
static void init_gpio_clocks(void) {
    MXC_GCR->pclkdis0 &= ~(MXC_F_GCR_PCLKDIS0_GPIO0 | MXC_F_GCR_PCLKDIS0_GPIO1);
    MXC_LPGCR->pclkdis &= ~MXC_F_LPGCR_PCLKDIS_GPIO2;
}

/**
 * @brief Initialize UART
 * 
 * Only done on AP since components never need UART.
 */
static void init_uart(void) {
#if IS_AP
    const int init_ret = MXC_UART_Init(MXC_UART_GET_UART(CONSOLE_UART),
                                       CONSOLE_BAUD, MXC_UART_IBRO_CLK);
    UTIL_ASSERT(init_ret == E_NO_ERROR);
#endif  // IS_AP
}

/**
 * @brief Initialize led
 */
static void init_led(void) {
    const uint32_t led_mask = MXC_GPIO_PIN_0 | MXC_GPIO_PIN_1 | MXC_GPIO_PIN_2;

    mxc_gpio_cfg_t cfg;
    cfg.port = MXC_GPIO2;
    cfg.mask = led_mask;
    cfg.func = MXC_GPIO_FUNC_OUT;
    cfg.pad = MXC_GPIO_PAD_NONE;
    cfg.vssel = MXC_GPIO_VSSEL_VDDIOH;

    const int init_ret = MXC_GPIO_Config(&cfg);
    UTIL_ASSERT(init_ret == E_NO_ERROR);

    // Turn all LEDs off
    MXC_GPIO2->outen_set = led_mask;
    MXC_GPIO2->out_set = led_mask;
}
