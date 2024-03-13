/**
 * @file comm_link_phy.c
 * @author Plaid Parliament of Pwning
 * @brief Prototypes for the physical layer side of communications
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */
#include "comm_link_phy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "comm_link_def.h"
#include "comm_link_tmr.h"
#include "gpio.h"
#include "util.h"  // For UTIL_ASSERT

/********** CONFIGURATION ***********/

/**
 * @brief The main timer used by the link layer
 */
#define LINK_TIMER MXC_TMR0  // DO NOT use this timer elsewhere

/**
 * @brief Logic levels on the pin will remain unchanged for at least this long
 */
#define LINK_TX_SAMPLE_TIME_TICKS ((uint32_t)100)
// 30 MHz / (100 * 3) == 100 kbps

/**
 * @brief  The time until the first edge is generated
 */
#define LINK_TX_TICKS_UNTIL_FIRST_EDGE (LINK_TX_SAMPLE_TIME_TICKS * 3)

/**
 * @brief The maximum time allowed for transmitting the waveform of a packet
 */
#define LINK_MAX_TX_TIME_TICKS (LINK_TMR_PERIOD_TICKS / 2)

/**
 * @brief Timing tolerances for each interval between edges when receiving
 */
#define LINK_RX_INTERVAL_TOLERANCE_TICKS (LINK_TX_SAMPLE_TIME_TICKS / 2)

/**
 * @brief The time of an acknowledgement signal
 */
#define LINK_ACK_TICKS (LINK_TX_SAMPLE_TIME_TICKS * LINK_TX_SAMPLES_PER_BIT)

/********** CONFIGURATION END ***********/

/********** FORWARD DECLARATIONS ***********/

static void link_init_time_buf(uint32_t *time_buf);
static inline uint32_t link_read_time_buf(const uint32_t *time_buf,
                                          size_t index)
    __attribute__((always_inline));
static inline void link_write_time_buf(uint32_t *time_buf, size_t index,
                                       uint32_t time)
    __attribute__((always_inline));

static link_ret_t link_compute_edge_time(const uint8_t *serialized_packet_buf,
                                         size_t num_bits);
static link_ret_t link_generate_waveform(size_t num_edges);
static link_ret_t link_generate_waveform_realtime(size_t num_edges);

static int32_t link_capture_waveform(size_t max_num_edges);
static int32_t link_capture_waveform_realtime(size_t max_num_edges);
static int32_t link_decode_edge_intervals(uint8_t *serialized_packet_buf,
                                          size_t num_edges);
static link_ret_t link_check_timing(bool bit, uint32_t high_interval,
                                    uint32_t low_interval);
static bool link_violates_timing(uint32_t interval, uint32_t interval_target);

/********** FORWARD DECLARATIONS END ***********/

/********** BUFFERS ***********/

/**
 * @brief The maximum number of edges produced by sending a packet
 */
#define LINK_MAX_NUM_EDGES (LINK_MAX_PACKET_SIZE * 8 * 2)
// 8 bits per byte, 2 edges per bit

/**
 * @brief The size of the epilogue of time buffers, which are filled with 0s
 */
#define LINK_TIME_BUF_EPILOGUE_SIZE ((size_t)4)

/**
 * @brief The total size of time buffers
 */
#define LINK_TIME_BUF_SIZE (LINK_MAX_NUM_EDGES + LINK_TIME_BUF_EPILOGUE_SIZE)

/**
 * @brief The value time buffers are initialized to, MUST be >= LINK_TMR_PERIOD_TICKS
 */
#define LINK_TIME_BUF_INITIAL_VALUE ((uint32_t)0xffffffff)

/**
 * @brief Buffer for the time to toggle the pin
 */
static uint32_t link_send_edge_time_buf[LINK_TIME_BUF_SIZE] = {0};

/**
 * @brief Buffer for the time after each detected edge
 */
static uint32_t link_receive_edge_interval_buf[LINK_TIME_BUF_SIZE] = {0};

/**
 * @brief Initialize the time buffer
 * 
 * @param time_buf time buffer pointer
 */
static void link_init_time_buf(uint32_t *time_buf) {
    // Fill the time buffer with LINK_TIME_BUF_INITIAL_VALUE
    for (size_t index = 0; index < LINK_MAX_NUM_EDGES; index++) {
        time_buf[index] = LINK_TIME_BUF_INITIAL_VALUE;
    }

    // Fill the epilogue of the time buffer with 0s
    for (size_t index = LINK_MAX_NUM_EDGES; index < LINK_TIME_BUF_SIZE;
         index++) {
        time_buf[index] = (uint32_t)0;
    }
}

/**
 * @brief Read from the time buffer at given index
 * 
 * @param time_buf time buffer pointer
 * @param index index
 * @return value at the index in the buffer
 */
static inline uint32_t link_read_time_buf(const uint32_t *time_buf,
                                          size_t index) {
    UTIL_ASSERT(index < LINK_MAX_NUM_EDGES);

    // Valid times and time intervals are always < LINK_TMR_PERIOD_TICKS
    const uint32_t read_time = time_buf[index];
    UTIL_ASSERT(read_time < LINK_TMR_PERIOD_TICKS);

    return read_time;
}

/**
 * @brief Write to the time buffer at given index
 * 
 * @param time_buf time buffer pointer
 * @param index index
 * @param time value to write
 */
static inline void link_write_time_buf(uint32_t *time_buf, size_t index,
                                       uint32_t time) {
    UTIL_ASSERT(index < LINK_MAX_NUM_EDGES);

    // The buffer is initially filled with LINK_TIME_BUF_INITIAL_VALUE
    const uint32_t read_time = time_buf[index];
    UTIL_ASSERT(read_time == LINK_TIME_BUF_INITIAL_VALUE);

    time_buf[index] = time;
}

/********** BUFFERS END ***********/

/********** GPIO ***********/

#define LINK_GPIO_PORT MXC_GPIO0
#define LINK_GPIO_DATA_PIN MXC_GPIO_PIN_16  // Originally I2C SCL
#define LINK_GPIO_SYNC_PIN MXC_GPIO_PIN_17  // Originally I2C SDA

#define LINK_DATA_LEVEL ((bool)(LINK_GPIO_PORT->in & LINK_GPIO_DATA_PIN))
#define LINK_SYNC_LEVEL ((bool)(LINK_GPIO_PORT->in & LINK_GPIO_SYNC_PIN))

static bool link_gpio_initialized = false;

/**
 * @brief Initializes the gpio pins for the link layer
 */
void link_init_gpio(void) {
    UTIL_ASSERT(!link_gpio_initialized);

    mxc_gpio_cfg_t cfg;
    cfg.port = LINK_GPIO_PORT;
    cfg.mask = LINK_GPIO_DATA_PIN | LINK_GPIO_SYNC_PIN;
    cfg.pad = MXC_GPIO_PAD_NONE;       // No pull-up or pull-down
    cfg.func = MXC_GPIO_FUNC_OUT;      // Output pin (input still works)
    cfg.vssel = MXC_GPIO_VSSEL_VDDIO;  // Output voltage is VDDIO
    const int config_ret = MXC_GPIO_Config(&cfg);
    UTIL_ASSERT(config_ret == E_NO_ERROR);

    // Enable input on both pins
    LINK_GPIO_PORT->inen |= LINK_GPIO_DATA_PIN | LINK_GPIO_SYNC_PIN;

    if (IS_AP) {
        // As the AP, make both pin output-enabled and LOW
        LINK_GPIO_PORT->out_clr = LINK_GPIO_DATA_PIN | LINK_GPIO_SYNC_PIN;
        LINK_GPIO_PORT->outen_set = LINK_GPIO_DATA_PIN | LINK_GPIO_SYNC_PIN;
    } else {
        // As a Component, make both pin output-disabled and HIGH
        LINK_GPIO_PORT->out_set = LINK_GPIO_DATA_PIN | LINK_GPIO_SYNC_PIN;
        LINK_GPIO_PORT->outen_clr = LINK_GPIO_DATA_PIN | LINK_GPIO_SYNC_PIN;
    }

    link_gpio_initialized = true;
}

/********** GPIO END ***********/

/********** SEND ***********/

/**
 * @brief Number of samples per bit
 */
#define LINK_TX_SAMPLES_PER_BIT ((uint32_t)3)

/**
 * @brief Edge timing for sending
 */
#define LINK_TX_0_HIGH_TIME_TICKS (LINK_TX_SAMPLE_TIME_TICKS * 1)
#define LINK_TX_0_LOW_TIME_TICKS (LINK_TX_SAMPLE_TIME_TICKS * 2)
#define LINK_TX_1_HIGH_TIME_TICKS (LINK_TX_SAMPLE_TIME_TICKS * 2)
#define LINK_TX_1_LOW_TIME_TICKS (LINK_TX_SAMPLE_TIME_TICKS * 1)

/**
 * @brief Number of ticks to maintain LOW to indicate a STOP condition
 */
#define LINK_TX_STOP_CONDITION_TICKS \
    (LINK_TX_SAMPLE_TIME_TICKS * LINK_TX_SAMPLES_PER_BIT * 2)

/**
 * @brief Sends a serialized packet
 * 
 * @param serialized_packet_buf buffer that contains the serialized packet
 * @param serialized_packet_size length of the buffer
 * @return link_ret_t 
 */
link_ret_t link_send_serialized_packet(const uint8_t *serialized_packet_buf,
                                       size_t serialized_packet_size) {
    UTIL_ASSERT(link_gpio_initialized);
    UTIL_ASSERT(serialized_packet_buf);
    UTIL_ASSERT(serialized_packet_size <= LINK_MAX_PACKET_SIZE);

    const size_t num_bits = serialized_packet_size * 8;
    const size_t num_edges = num_bits * 2;
    UTIL_ASSERT(num_edges <= LINK_MAX_NUM_EDGES);

    link_init_time_buf(link_send_edge_time_buf);

    // Pre-compute the time to toggle the pin
    const link_ret_t time_ret =
        link_compute_edge_time(serialized_packet_buf, num_bits);
    if (time_ret != LINK_OK) {
        return time_ret;
    }

    // Generate the waveform on the data pin
    return link_generate_waveform(num_edges);
}

/**
 * @brief Converts a byte stream to a stream of timestamps when edges are seen when sending over physical media
 * 
 * @param serialized_packet_buf the seralized packet buffer
 * @param num_bits Number of bits in the seralized packet
 * @return 0 on success, negative on error
 */
static link_ret_t link_compute_edge_time(const uint8_t *serialized_packet_buf,
                                         size_t num_bits) {
    UTIL_ASSERT(serialized_packet_buf);

    const size_t num_edges = num_bits * 2;
    UTIL_ASSERT(num_edges <= LINK_MAX_NUM_EDGES);

    const uint64_t total_ticks = (uint64_t)LINK_TX_TICKS_UNTIL_FIRST_EDGE +
                                 (uint64_t)LINK_TX_STOP_CONDITION_TICKS +
                                 (uint64_t)num_bits *
                                     (uint64_t)LINK_TX_SAMPLES_PER_BIT *
                                     (uint64_t)LINK_TX_SAMPLE_TIME_TICKS;
    UTIL_ASSERT(total_ticks <= (uint64_t)LINK_MAX_TX_TIME_TICKS);

    size_t edge_index = 0;
    uint32_t next_edge_ticks = LINK_TX_TICKS_UNTIL_FIRST_EDGE;
    for (size_t bit_index = 0; bit_index < num_bits; bit_index++) {
        const size_t byte_index = bit_index / 8;
        UTIL_ASSERT(byte_index < LINK_MAX_PACKET_SIZE);
        const uint8_t byte_offset = (uint8_t)(bit_index % 8);

        const uint8_t byte = serialized_packet_buf[byte_index];
        const bool bit = byte & (((uint8_t)1) << byte_offset);

        // The first rising edge is implicitly at LINK_TX_TICKS_UNTIL_FIRST_EDGE
        if (!bit) {  // 0 bit
            // Falling edge
            next_edge_ticks += LINK_TX_0_HIGH_TIME_TICKS;
            link_write_time_buf(link_send_edge_time_buf, edge_index,
                                next_edge_ticks);
            edge_index++;

            // Rising edge
            next_edge_ticks += LINK_TX_0_LOW_TIME_TICKS;
            link_write_time_buf(link_send_edge_time_buf, edge_index,
                                next_edge_ticks);
            edge_index++;
        } else {  // 1 bit
            // Falling edge
            next_edge_ticks += LINK_TX_1_HIGH_TIME_TICKS;
            link_write_time_buf(link_send_edge_time_buf, edge_index,
                                next_edge_ticks);
            edge_index++;

            // Rising edge
            next_edge_ticks += LINK_TX_1_LOW_TIME_TICKS;
            link_write_time_buf(link_send_edge_time_buf, edge_index,
                                next_edge_ticks);
            edge_index++;
        }
    }
    UTIL_ASSERT(edge_index == num_edges);  // Check for overflow

    return LINK_OK;
}

/**
 * @brief Generate a wave on physical media given a bitstream
 * 
 * This function is mostly just a wrapper over link_generate_waveform_realtime.
 * 
 * @param num_edges num of edges to generate waves for
 * @return 0 on success, negative on error
 */
static link_ret_t link_generate_waveform(size_t num_edges) {
    UTIL_ASSERT(num_edges <= LINK_MAX_NUM_EDGES);

    // At this point:
    // As the AP, the data pin should be output-enabled and LOW
    // As a Component, the data pin should be output-disabled and HIGH

    if (!IS_AP) {
        // As a Component, wait for the data pin to be released to HIGH
        while (!LINK_DATA_LEVEL) {  // LOW
            // Wait indefinitely
        }
        // This wait needs to be before starting the timer, otherwise
        // LINK_TX_TICKS_UNTIL_FIRST_EDGE would not be enough

        // Enable output on the data pin and hold it HIGH
        LINK_GPIO_PORT->out_set = LINK_GPIO_DATA_PIN;
        LINK_GPIO_PORT->outen_set = LINK_GPIO_DATA_PIN;
    }

    link_start_timer(LINK_TIMER, true);  // One-shot mode

    const link_ret_t ret = link_generate_waveform_realtime(num_edges);

    if (IS_AP) {
        // As the AP, hold the data pin LOW to jam the bus while it's idle
        LINK_GPIO_PORT->out_clr = LINK_GPIO_DATA_PIN;
    } else {
        // As a Component, disable output on the data pin to release it
        LINK_GPIO_PORT->outen_clr = LINK_GPIO_DATA_PIN;
    }

    // At this point:
    // As the AP, the data pin should be output-enabled and LOW
    // As a Component, the data pin should be output-disabled and HIGH

    link_stop_timer(LINK_TIMER);  // Stopping the timer is NOT mandatory
    return ret;
}

/**
 * @brief Does the heavy lifting of sending every bit on the wire
 * 
 * @param num_edges number of edges when the voltage flips on the wire
 * @return 0 on success, negative on error
 */
static link_ret_t link_generate_waveform_realtime(size_t num_edges) {
    UTIL_ASSERT(num_edges <= LINK_MAX_NUM_EDGES);

    // Ensure that the initial level of the data pin is what's expected
    // The AP expects LOW while the Component expects HIGH
    if ((bool)IS_AP == LINK_DATA_LEVEL) {
        return LINK_ERR_BUS;  // Got HIGH as the AP or got LOW as a Component
    }

    // Pull down the data pin because the starting level is LOW
    LINK_GPIO_PORT->out_clr = LINK_GPIO_DATA_PIN;

    bool next_data_level = true;  // The first edge is a rising edge
    uint32_t next_edge_ticks = LINK_TX_TICKS_UNTIL_FIRST_EDGE;

    size_t edge_index = 0;
    while (edge_index < num_edges) {
        // Wait for the time to generate the next edge
        do {
            // Wait for rising edge, observing the pin for inconsistencies
            if (LINK_DATA_LEVEL == next_data_level) {
                return LINK_ERR_BUS;  // Inconsistent level on the data pin
            }
        } while (LINK_TIMER->cnt < next_edge_ticks);

        // Set the data pin to the next level
        if (next_data_level) {
            LINK_GPIO_PORT->out_set = LINK_GPIO_DATA_PIN;
        } else {
            LINK_GPIO_PORT->out_clr = LINK_GPIO_DATA_PIN;
        }

        next_data_level = !next_data_level;
        next_edge_ticks =
            link_read_time_buf(link_send_edge_time_buf, edge_index);
        edge_index++;
    }
    UTIL_ASSERT(edge_index == num_edges);  // Check for overflow

    // Final rising edge for the stop condition
    while (LINK_TIMER->cnt < next_edge_ticks) {
        // Wait for rising edge, observing the pin for inconsistencies
        if (LINK_DATA_LEVEL) {
            return LINK_ERR_BUS;  // Inconsistent level on the data pin
        }
    }
    if (!IS_AP) {
        // As a Component, send the final rising edge by releasing the data pin
        LINK_GPIO_PORT->outen_clr = LINK_GPIO_DATA_PIN;  // Disable output
    }
    LINK_GPIO_PORT->out_set = LINK_GPIO_DATA_PIN;

    // Hold HIGH for LINK_TX_STOP_CONDITION_TICKS
    next_edge_ticks += LINK_TX_STOP_CONDITION_TICKS;
    while (LINK_TIMER->cnt < next_edge_ticks) {
        // Wait, observing the pin for inconsistencies only as the AP,
        // because as a Component the data pin is released
        if (IS_AP && !LINK_DATA_LEVEL) {
            return LINK_ERR_BUS;  // Inconsistent level on the data pin
        }
    }

    return LINK_OK;
}

/********** SEND END ***********/

/********** RECEIVE ***********/

/**
 * @brief The time between two detected edges above which would trigger a termination
 */
#define LINK_RX_STOP_CONDITION_TICKS (LINK_TX_STOP_CONDITION_TICKS / 2)

/**
 * @brief The mask for valid bits of the time between two edges in ticks
 */
#define LINK_EDGE_INTERVAL_MASK ((uint32_t)0x7fffffff)  // MUST be 2^31 - 1

/**
 * @brief Receives a packet and decodes it into a bytestream
 * 
 * @param serialized_packet_buf output buffer where the bytestream is written to
 * @param max_message_size max message size possible in bytes
 * @return Size of the received packet if non-negative, error code if negative
 */
int32_t link_receive_serialized_packet(uint8_t *serialized_packet_buf,
                                       size_t max_message_size) {
    UTIL_ASSERT(link_gpio_initialized);
    UTIL_ASSERT(serialized_packet_buf);
    UTIL_ASSERT(max_message_size <= LINK_MAX_MESSAGE_SIZE);

    const size_t max_packet_size = max_message_size + LINK_HEADER_SIZE;
    UTIL_ASSERT(max_packet_size <= LINK_MAX_PACKET_SIZE);

    const size_t max_num_bits = max_packet_size * 8;
    const size_t max_num_edges = max_num_bits * 2;
    UTIL_ASSERT(max_num_edges <= LINK_MAX_NUM_EDGES);

    link_init_time_buf(link_receive_edge_interval_buf);

    // Wait for a waveform on the data pin and capture it
    const int32_t num_edges_ret = link_capture_waveform(max_num_edges);
    if (num_edges_ret < 0) {
        return num_edges_ret;  // Error code
    }
    const size_t num_edges = (size_t)num_edges_ret;

    // Decode the waveform into a serialized packet
    const int32_t packet_size_ret =
        link_decode_edge_intervals(serialized_packet_buf, num_edges);
    if (packet_size_ret < 0) {
        return packet_size_ret;  // Error code
    }
    const size_t packet_size = (size_t)packet_size_ret;

    UTIL_ASSERT(LINK_CAN_FIT_IN_INT32(packet_size));
    return (int32_t)packet_size;
}

/**
 * @brief Senses the wires to convert it to an edge array
 * 
 * Mostly a wrapper function that calls link_capture_waveform_realtime to do the heavylifting.
 * 
 * @param max_num_edges max num of edges 
 * @return actual number of edges captured
 */
static int32_t link_capture_waveform(size_t max_num_edges) {
    UTIL_ASSERT(max_num_edges <= LINK_MAX_NUM_EDGES);

    link_start_timer(LINK_TIMER, false);  // Continuous mode

    // At this point:
    // As the AP, the data pin should be output-enabled and LOW
    // As a Component, the data pin should be output-disabled and HIGH

    if (IS_AP) {
        // As the AP, disable output on the data pin to release it, signaling
        // the component to start sending
        LINK_GPIO_PORT->outen_clr = LINK_GPIO_DATA_PIN;

        // Wait for the data pin to be pulled HIGH by the pullup resistor
        while (!LINK_DATA_LEVEL) {  // LOW
            // Wait indefinitely
        }
    }

    const int32_t ret = link_capture_waveform_realtime(max_num_edges);

    if (IS_AP) {
        // As the AP, re-enable output on the data pin and hold it LOW to jam
        // the bus while it's idle
        LINK_GPIO_PORT->out_clr = LINK_GPIO_DATA_PIN;
        LINK_GPIO_PORT->outen_set = LINK_GPIO_DATA_PIN;
    } else {
        // As a Component, disable output on the data pin to release it
        LINK_GPIO_PORT->outen_clr = LINK_GPIO_DATA_PIN;
    }

    // At this point:
    // As the AP, the data pin should be output-enabled and LOW
    // As a Component, the data pin should be output-disabled and HIGH

    link_stop_timer(LINK_TIMER);  // Stopping the timer is NOT mandatory
    return ret;
}

/**
 * @brief Captures the wave on wire and converts it to bits
 * 
 * Does the heavylifting of making sense of whether a bit was high or low and writing it to a buffer.
 * 
 * @param max_num_edges max number of edges to capture
 * @return actual number of edges captured
 */
static int32_t link_capture_waveform_realtime(size_t max_num_edges) {
    UTIL_ASSERT(max_num_edges <= LINK_MAX_NUM_EDGES);

    // Wait for the data pin to be LOW, because waveforms must start with LOW
    while (LINK_DATA_LEVEL) {  // HIGH
        // Wait indefinitely
    }

    const uint32_t stop_condition_ticks = LINK_RX_STOP_CONDITION_TICKS;

    bool first_edge_detected = false;
    bool prev_data_level = false;     // The data pin is now LOW
    uint32_t prev_edge_ticks = 0;     // Initial value doesn't matter
    bool current_data_level = false;  // Initial value doesn't matter
    uint32_t now_ticks = 0;           // Initial value doesn't matter
    uint32_t interval_ticks = 0;      // Initial value doesn't matter

    size_t edge_index = 0;
    while (edge_index < max_num_edges) {
        bool stop_condition_detected = false;

        // Wait for edge
        do {  // The loop body must run at least once per edge
            // Capture data and time
            current_data_level = LINK_DATA_LEVEL;
            now_ticks = LINK_TIMER->cnt;

            // Compute time since previous edge
            interval_ticks =
                (now_ticks - prev_edge_ticks) & LINK_EDGE_INTERVAL_MASK;

            // Check for stop condition, except for the first edge
            if (interval_ticks > stop_condition_ticks && first_edge_detected) {
                stop_condition_detected = true;
                break;
            }
        } while (current_data_level == prev_data_level);

        if (stop_condition_detected) {
            break;  // Will NOT log the stop condition
        }

        // Log the time since the previous edge, except for the first edge,
        // because it has no previous edge
        if (first_edge_detected) {  // The current edge is NOT the first edge
            link_write_time_buf(link_receive_edge_interval_buf, edge_index,
                                interval_ticks);
            edge_index++;
        } else {  // The current edge is the first edge
            first_edge_detected = true;
        }

        prev_data_level = current_data_level;
        prev_edge_ticks = now_ticks;
    }
    UTIL_ASSERT(edge_index <= max_num_edges);  // Check for overflow

    UTIL_ASSERT(LINK_CAN_FIT_IN_INT32(edge_index));
    return (int32_t)edge_index;
}

/**
 * @brief Decode edge intervals from the received data and serialize into a packet
 * 
 * @param serialized_packet_buf serialized packet
 * @param num_edges number of edges
 * @return number of bytes if positive, error if negative
 */
static int32_t link_decode_edge_intervals(uint8_t *serialized_packet_buf,
                                          size_t num_edges) {
    UTIL_ASSERT(serialized_packet_buf);
    UTIL_ASSERT(num_edges <= LINK_MAX_NUM_EDGES);

    if (num_edges % 2 != 0) {
        return LINK_ERR_SIZE;  // Odd number of edges
    }

    const size_t num_bits = num_edges / 2;
    if (num_bits % 8 != 0) {
        return LINK_ERR_SIZE;  // Not an integer number of bytes
    }

    const size_t packet_size = num_bits / 8;
    UTIL_ASSERT(packet_size <= LINK_MAX_PACKET_SIZE);

    size_t edge_index = 0;
    for (size_t bit_index = 0; bit_index < num_bits; bit_index++) {
        const uint32_t high_interval =
            link_read_time_buf(link_receive_edge_interval_buf, edge_index);
        edge_index++;

        const uint32_t low_interval =
            link_read_time_buf(link_receive_edge_interval_buf, edge_index);
        edge_index++;

        // Decode a bit by comparing the length of intervals
        const bool bit = high_interval >= low_interval;

        // Check for timing violations
        const link_ret_t check_timing_ret =
            link_check_timing(bit, high_interval, low_interval);
        if (check_timing_ret != LINK_OK) {
            return check_timing_ret;  // Error code
        }

        // Log the decoded bit
        const size_t byte_index = bit_index / 8;
        UTIL_ASSERT(byte_index < LINK_MAX_PACKET_SIZE);
        const uint8_t byte_offset = (uint8_t)(bit_index % 8);

        if (byte_offset == 0) {
            // Beginning of a byte, initialize with 0
            serialized_packet_buf[byte_index] = 0;
        }

        serialized_packet_buf[byte_index] |= ((uint8_t)bit) << byte_offset;
    }
    UTIL_ASSERT(edge_index == num_edges);

    UTIL_ASSERT(LINK_CAN_FIT_IN_INT32(packet_size));
    return (int32_t)packet_size;
}

/**
 * @brief Checks if the high and low intervals violate tolerance levels
 * 
 * @param bit 1 or 0
 * @param high_interval time that the link is high
 * @param low_interval time that the link is low
 * @return link_ret_t 
 */
static link_ret_t link_check_timing(bool bit, uint32_t high_interval,
                                    uint32_t low_interval) {
    uint32_t high_interval_target = 0;
    uint32_t low_interval_target = 0;
    if (!bit) {  // 0 bit
        high_interval_target = LINK_TX_0_HIGH_TIME_TICKS;
        low_interval_target = LINK_TX_0_LOW_TIME_TICKS;
    } else {  // 1 bit
        high_interval_target = LINK_TX_1_HIGH_TIME_TICKS;
        low_interval_target = LINK_TX_1_LOW_TIME_TICKS;
    }

    if (link_violates_timing(high_interval, high_interval_target) ||
        link_violates_timing(low_interval, low_interval_target)) {
        return LINK_ERR_TIMING;
    }

    return LINK_OK;
}

/**
 * @brief Checks if timing difference is more than tolerance level
 * 
 * @param interval first interval endpoint
 * @param interval_target second interval endpoint
 * @return true if violated, else false
 */
static bool link_violates_timing(uint32_t interval, uint32_t interval_target) {
    // Compare the absolute value of the difference against
    // LINK_RX_INTERVAL_TOLERANCE_TICKS
    if (interval >= interval_target) {
        return interval - interval_target > LINK_RX_INTERVAL_TOLERANCE_TICKS;
    } else {
        return interval_target - interval > LINK_RX_INTERVAL_TOLERANCE_TICKS;
    }
}

/********** RECEIVE END ***********/

/********** ACK ***********/

/**
 * @brief Sends an ack
 * 
 * AP would never call this. 
 * Should always succeed.
 */
void link_send_ack(void) {
    UTIL_ASSERT(link_gpio_initialized);

    if (IS_AP) {
        return;  // The AP doesn't need to send an ACK
    }

    // At this point:
    // (The AP should not be able to reach this point)
    // As a Component, the sync pin should be output-disabled and LOW

    // Wait for the sync pin to be released to HIGH
    while (!LINK_SYNC_LEVEL) {
        // Wait indefinitely
    }

    link_start_timer(LINK_TIMER, true);  // One-shot mode

    // Enable output on the sync pin and pull it down
    LINK_GPIO_PORT->out_clr = LINK_GPIO_SYNC_PIN;
    LINK_GPIO_PORT->outen_set = LINK_GPIO_SYNC_PIN;

    // Wait for LINK_ACK_TICKS ticks
    while (LINK_TIMER->cnt < LINK_ACK_TICKS) {
        // Wait
    }

    // Disable output on the sync pin to release it
    LINK_GPIO_PORT->outen_clr = LINK_GPIO_SYNC_PIN;

    // At this point:
    // (The AP should not be able to reach this point)
    // As a Component, the sync pin should be output-disabled and LOW

    link_stop_timer(LINK_TIMER);  // Stopping the timer is NOT mandatory
}

/**
 * @brief Wait for an ack 
 * 
 * Component would never call this.
 * 
 * @param timeout_ticks wait timeout in ticks
 * @return 0 on success, negative on error
 */
link_ret_t link_wait_ack(uint32_t timeout_ticks) {
    UTIL_ASSERT(link_gpio_initialized);

    if (!IS_AP) {
        return LINK_OK;  // A Component doesn't need to wait for an ACK
    }

    // At this point:
    // As the AP, the sync pin should be output-enabled and LOW
    // (A Component should not be able to reach this point)

    // Disable output on the sync pin to release it
    LINK_GPIO_PORT->outen_clr = LINK_GPIO_SYNC_PIN;

    link_start_timer(LINK_TIMER, true);  // One-shot mode

    // Wait for the sync pin to become LOW
    link_ret_t ret = LINK_OK;
    while (LINK_SYNC_LEVEL) {  // HIGH
        if (LINK_TIMER->cnt >= timeout_ticks) {
            ret = LINK_ERR_TIMEOUT;
            break;
        }
    }

    // Enable output on the sync pin and hold it LOW
    LINK_GPIO_PORT->out_clr = LINK_GPIO_SYNC_PIN;
    LINK_GPIO_PORT->outen_set = LINK_GPIO_SYNC_PIN;

    // At this point:
    // As the AP, the sync pin should be output-enabled and LOW
    // (A Component should not be able to reach this point)

    link_stop_timer(LINK_TIMER);  // Stopping the timer is NOT mandatory
    return ret;
}

/********** ACK END ***********/
