#include "trng.h"
#include "inc/rng.h"

unsigned int get_random_trng(void) {
    uint8_t var_rnd_no[4] = {0};
    uint8_t var_rnd_no_2[4] = {0};
    MXC_TRNG_Random(var_rnd_no, 4);
    MXC_TRNG_Random(var_rnd_no_2, 4);
    if (*((unsigned int *)var_rnd_no) == *((unsigned int *)var_rnd_no_2)) {
        return -1;
    }
    return *((unsigned int *)var_rnd_no);
}