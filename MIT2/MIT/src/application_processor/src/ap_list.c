/**
 * @file ap_list.c
 * @author MIT TechSec
 * @brief List-related functions for AP
 * @date 2024
 */

#include "ap_common.h"

static void mit_scan(i2c_addr_t addr);

// Scan I2C address space for connected components
int scan_components() {
    // This section differs from our normal messaging scheme
    // Here, we don't send well-formed packets, and messages are unauthenticated.
    // However, we can tell it is not part of our normal messaging scheme by the
    // fact that it is only 4 bytes, and thus shorter than any mit_packet_t.

    // Print out provisioned component IDs
    for (unsigned id = 0; id < COMPONENT_CNT; id++) {
        print_info("P>0x%08x\n", get_component_id(id));
    }

    // Scan scan command to each component 
    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // I2C Blacklist:
        // 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }

        // Send component_id to addr
        mit_scan(addr);

    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

void mit_scan(i2c_addr_t addr) {
    int ret, len;
    uint8_t * buf = get_i2c_rx_buffer();
    mit_comp_id_t component_id = (mit_comp_id_t)addr;

    // Send a 4-byte scan packet
    ret = send_packet(addr, sizeof(mit_comp_id_t), &component_id);
    if (ret != SUCCESS_RETURN) {
        return;
    }

    // Receive a 4-byte scan packet
    len = poll_and_receive_packet(addr, buf);
    if (len != sizeof(mit_comp_id_t)) {
        return;
    }

    // Copy component_id out of buf
    component_id = *(mit_comp_id_t *)buf;

    // Print the unauthenticated component ID
    print_info("F>0x%08x\n", component_id);

    return;
}
