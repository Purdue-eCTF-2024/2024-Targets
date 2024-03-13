#!/bin/bash

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
export LINKERFILE=../common/firmware.ld
export STARTUPFILE=../common/startup_firmware.S
export ENTRY=firmware_startup

PATCH_DIR=./build/patches

patches=""
patches+=" ${PATCH_DIR}/boot-blob-page.bin,0x1003E000"
patches+=" ${PATCH_DIR}/defense-lockout.bin,0x10040000"
patches+=" ${PATCH_DIR}/entropy.bin,0x10042000"
patches+=" ${PATCH_DIR}/keys.bin,0x10044000"

PATCHES=${patches} IS_AP=1 bash ../common/build.sh $1 ap
