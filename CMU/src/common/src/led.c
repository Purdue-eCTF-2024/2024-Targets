#include "led.h"

#include "gpio.h"
#include "max78000.h"
#include "util.h"  // For UTIL_ASSERT

#define NUM_LEDS ((size_t)3)

/**
 * @brief Led pins array
 */
static const uint32_t led_masks[NUM_LEDS] = {MXC_GPIO_PIN_0, MXC_GPIO_PIN_1,
                                             MXC_GPIO_PIN_2};

/**
 * @brief Switches on an Led
 * 
 * @param index index of the led
 */
void LED_On(size_t index) {
    UTIL_ASSERT(index < NUM_LEDS);

    const uint32_t mask = led_masks[index];
    MXC_GPIO2->outen_set = mask;
    MXC_GPIO2->out_clr = mask;
}

/**
 * @brief Switches off an Led
 * 
 * @param index index of the led
 */
void LED_Off(size_t index) {
    UTIL_ASSERT(index < NUM_LEDS);

    const uint32_t mask = led_masks[index];
    MXC_GPIO2->outen_set = mask;
    MXC_GPIO2->out_set = mask;
}
