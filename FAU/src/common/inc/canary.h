#define CANARY_BEGIN \
    MXC_TRNG_Init(); \
    int canaryval = MXC_TRNG_RandomInt(); \
    volatile int canary = canaryval;

#define CANARY_END \
    if ((canaryval ^ canary) != 0) MXC_SYS_Reset_Periph(MXC_SYS_RESET0_SYS);
