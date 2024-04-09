#include "host_messaging.h"

// Print a message through USB UART and then receive a line over USB UART
// size of buf has to be precised everywhere the recv_input fonction is called
void recv_input(const char *msg, char *buf, size_t n) {
    print_debug(msg);
    fflush(0);
    print_ack(); 
    fgets(buf, n , stdin);
    puts("");
}

// Prints a buffer of bytes as a hex string
void print_hex(uint8_t *buf, size_t len) {
    for (int i = 0; i < len; i++)
    	printf("%02x", buf[i]);
    printf("\n");
}
