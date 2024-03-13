MEMORY {
    ROM         (rx) : ORIGIN = 0x00000000, LENGTH = 0x00010000 /* 64kB ROM */
    BOOTLOADER  (rx) : ORIGIN = 0x10000000, LENGTH = 0x0000E000 /* Bootloader flash */
    FLASH       (rx) : ORIGIN = 0x1000E000, LENGTH = 0x00030000 /* Location of team firmware */
    FLASH_DATA  (rw) : ORIGIN = 0x1003E000, LENGTH = 0x00008000 /* Location of nonvolatile data */
    RESERVED    (rw) : ORIGIN = 0x10046000, LENGTH = 0x00038000 /* Reserved */
    ROM_BL_PAGE (rw) : ORIGIN = 0x1007E000, LENGTH = 0x00002000 /* Reserved */
    SRAM_CODE   (rwx): ORIGIN = 0x20000000, LENGTH = 0x00004000 /* 16kB decrypted code */
    MXCF_CODE   (rwx): ORIGIN = 0x20004000, LENGTH = 0x00004000 /* 16kB "flashprog" code */
    SRAM        (rwx): ORIGIN = 0x20008000, LENGTH = 0x00018000 /* 128kB SRAM */
}

/*
    0x1000_E000 - 0x1003_DFFF = Code
    0x1003_E000 - 0x1003_FFFF = Boot Blob + Provisioned Components List
    0x1004_0000 - 0x1004_1FFF = Lockout Counters
    0x1004_2000 - 0x1004_3FFF = RNG Seed / State
    0x1004_4000 - 0x1004_5FFF = (AP: Boot and attestation root keys) (C: ID, attestation data, SSS_id)
    0x1004_5FFF - 0x1008_0000 = Unallowed region
*/

SECTIONS {
    .rom :
    {
        KEEP(*(.rom_vector))
        *(.rom_handlers*)
    } > ROM

    .text :
    {
        _text = .;
        KEEP(*(.isr_vector))
        KEEP(*(.firmware_startup))
        *(.text*)    /* program code */
        *(.rodata*)  /* read-only data: "const" */

        KEEP(*(.init))
        KEEP(*(.fini))

        /* C++ Exception handling */
        KEEP(*(.eh_frame*))
        _etext = .;
    } > FLASH

    .code.encrypted :
    {
        _code_decrypted = .;
        . = ALIGN(4);
        KEEP(*(.encrypted_text*))
        KEEP(*(.encrypted_rodata*))
        . = ALIGN(4);
        KEEP(*(.encrypted_data*))
        . = ALIGN(4);

        /* If the section is larger than 0x4000 bytes, it will overflow SRAM_CODE and fail */
        . = ALIGN(0x4000) - 40;
        
        _ecode_decrypted = .;

        /* Reserve space in the section for the encryption metadata. */
        /* When we actually store the text in flash, this space will be at the beginning. */
        . = . + 40;

    } > SRAM_CODE AT>FLASH
    _code_encrypted = LOADADDR(.code.encrypted);
    
    .flashprog :
    {
        _flashprog = .;
        . = ALIGN(4);
        *(.flashprog*)
        . = ALIGN(4);

        . = ALIGN(0x2000);

        /* The other half of this section should be unused */
        . = . + 0x2000; 

        /* If the code is larger than 0x2000 bytes, it will overflow MXCF_CODE and fail */

        _eflashprog = .;
    } > MXCF_CODE AT>FLASH
    __load_flashprog = LOADADDR(.flashprog);

    .data :
    {
        _data = ALIGN(., 4);
        *(.data*)           /*read-write initialized data: initialized global variable*/

        /* These array sections are used by __libc_init_array to call static C++ constructors */
        . = ALIGN(4);
        /* preinit data */
        PROVIDE_HIDDEN (__preinit_array_start = .);
        KEEP(*(.preinit_array))
        PROVIDE_HIDDEN (__preinit_array_end = .);

        . = ALIGN(4);
        /* init data */
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
        PROVIDE_HIDDEN (__init_array_end = .);

        . = ALIGN(4);
        /* finit data */
        PROVIDE_HIDDEN (__fini_array_start = .);
        KEEP(*(SORT(.fini_array.*)))
        KEEP(*(.fini_array))
        PROVIDE_HIDDEN (__fini_array_end = .);

        _edata = ALIGN(., 4);
    } > SRAM AT>FLASH
    __load_data = LOADADDR(.data);


    .bss :
    {
        . = ALIGN(4);
        _bss = .;
        *(.bss*)     /*read-write zero initialized data: uninitialzed global variable*/
        *(COMMON)
        _ebss = ALIGN(., 4);
    } > SRAM

    .shared :
    {
        . = ALIGN(4);
        _shared = .;
        *(.mailbox*)
        . = ALIGN(4);
        *(.shared*)     /*read-write zero initialized data: uninitialzed global variable*/
        _eshared = ALIGN(., 4);
    } > SRAM
    __shared_data = LOADADDR(.shared);

    /* Set stack top to end of RAM, and stack limit move down by
     * size of stack_dummy section */
    __StackTop = ORIGIN(SRAM) + LENGTH(SRAM);
    __StackLimit = __StackTop - SIZEOF(.stack_dummy);

    /* .stack_dummy section doesn't contains any symbols. It is only
     * used for linker to calculate size of stack sections, and assign
     * values to stack symbols later */
    .stack_dummy (COPY):
    {
        *(.stack*)
    } > SRAM

    PROVIDE(__stack = __StackTop);

    /* Check if data + stack exceeds RAM limit */
    ASSERT(__StackLimit >= _ebss, "region RAM overflowed with stack")
}
