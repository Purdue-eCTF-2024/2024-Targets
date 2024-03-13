#include "util.h"

void do_spin_forever() {
    volatile int tmp = 1;
    while (tmp);
    __builtin_unreachable();
}
