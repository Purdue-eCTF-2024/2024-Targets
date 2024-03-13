#!/bin/bash

set -e

COMP_OR_AP=$2

# ========================== #
# Target and toolchain setup #
# ========================== #

BUILD_DIR="build/"
COMMON_DIR="../common"

TARGET=MAX78000

TARGET_UC=MAX78000
TARGET_LC=max78000

TARGET_REV=0x4131

BOARD=FTHR_RevA

PREFIX=arm-none-eabi

# The command for calling the compiler.
CC=${PREFIX}-gcc
CXX=${PREFIX}-g++
AS=${PREFIX}-as

# The command for calling the library archiver.
AR=${PREFIX}-ar

# The command for calling the linker.
LD=${PREFIX}-gcc

# The command for extracting images from the linked executables.
OBJCOPY=${PREFIX}-objcopy
OBJDUMP=${PREFIX}-objdump

# The command for stripping objects.
STRIP=${PREFIX}-strip

PROJECT=max78000
PROJECT_PLAINTEXT=max78000-plaintext

# ================================= #
# Source/Include Path Configuration #
# ================================= #

VPATH+=(.)
VPATH+=(src/)

VPATH+=(../msdk-lib/ICC)
VPATH+=(../msdk-lib/UART)
VPATH+=(../msdk-lib/GPIO)
VPATH+=(../msdk-lib/SYS)
VPATH+=(../msdk-lib/FLC)
VPATH+=(../msdk-lib/TMR)

IPATH+=(inc/)

IPATH+=(../msdk-lib)
IPATH+=(../msdk-lib/Include)
IPATH+=(../msdk-lib/IncludeMAX78000)
IPATH+=(../msdk-lib/PeriphDriversMAX78000/)
IPATH+=(../msdk-lib/I2C)

VPATH+=(../common/src)
IPATH+=(../common/inc)

# Append /*.c to all paths and glob-expand them to get a list of all C files
SRCS=(${VPATH[@]/%/\/*.c})

SRCS+=(${STARTUPFILE})
# SRCS+=("../msdk-lib/system_${TARGET_LC}.c")

#PROJECTMK ?= $(abspath ./project.mk)
#include project.mk
#$(info Loaded project.mk)

# Create output object file names
# SRCS_NOPATH := $(foreach NAME,$(SRCS),$(basename $(notdir $(NAME))).c)
# BINS_NOPATH := $(foreach NAME,$(BINS),$(basename $(notdir $(NAME))).bin)
# OBJS_NOPATH := $(SRCS_NOPATH:.c=.o)
# OBJS_NOPATH += $(BINS_NOPATH:.bin=.o)
# OBJS        := $(OBJS_NOPATH:%.o=$(BUILD_DIR)/%.o)
# OBJS        += $(PROJ_OBJS)


# The flags passed to the assembler.
AFLAGS=(-mthumb -mcpu=cortex-m4 -MD)

MFLOAT_ABI=softfp

# Option for setting the FPU to use
MFPU=fpv4-sp-d16
#MFPU ?= fpv4-sp-d16

# The flags passed to the compiler.
# fno-isolate-erroneous-paths-dereference disables the check for pointers with the value of 0
#  add this below when arm-none-eabi-gcc version is past 4.8 -fno-isolate-erroneous-paths-dereference                                \

# Universal optimization flags added to all builds
DEFAULT_OPTIMIZE_FLAGS=(-ffunction-sections -fdata-sections -fsingle-precision-constant -falign-functions=64)
DEFAULT_WARNING_FLAGS=(-Wall -Wno-format -Wdouble-promotion)

CFLAGS=(-mthumb                                                                \
       -mcpu=cortex-m4                                                         \
       -mfloat-abi=${MFLOAT_ABI}                                               \
       -mfpu=${MFPU}                                                           \
       -Wa,-mimplicit-it=thumb                                                 \
       ${MXC_OPTIMIZE_CFLAGS[@]}   											   \
       ${DEFAULT_OPTIMIZE_FLAGS[@]}  									       \
       ${DEFAULT_WARNING_FLAGS[@]}   									       \
       -MD                                                                     \
       -c)

CFLAGS+=(-fno-isolate-erroneous-paths-dereference)
CFLAGS+=(-DTARGET=${TARGET})
CFLAGS+=(-DTARGET_REV=${TARGET_REV})
CFLAGS+=(-falign-functions=64 -falign-loops=64)

# The flags passed to the linker.
LDFLAGS=(-mthumb                                                               \
        -mcpu=cortex-m4                                                        \
        -mfloat-abi=${MFLOAT_ABI}                                              \
        -mfpu=${MFPU}                                                          \
        -Xlinker --gc-sections                                                 \
	-Xlinker -Map -Xlinker ${BUILD_DIR}/${PROJECT}.map)
LDFLAGS+=(${PROJ_LDFLAGS[@]})
LDFLAGS+=(-nostartfiles -nostdlib)

# Add the include file paths to AFLAGS and CFLAGS.
AFLAGS+=(${IPATH[@]/#/-I})
CFLAGS+=(${IPATH[@]/#/-I})
LDFLAGS+=(${LIBPATH[@]/#/-L})

if [ -z "${POST_BOOT_ENABLED}" ]; then
	POST_BOOT_ENABLED=0
fi

################################################################################
# Goals

function clean() {
	rm -rf "${BUILD_DIR}"
}

function all() {
	mkdir -p "${BUILD_DIR}"

	# Remove any secrets from the headers,
	# to prevent accidental inclusion in the binary.
	EXTRA_CFLAGS=$(poetry run python "${COMMON_DIR}/scripts/parse_header.py" ${COMP_OR_AP} "inc/ectf_params.h" "${BUILD_DIR}/params.pickle")
	rm inc/ectf_params.h

	OBJS=()

	# Build all .o files
	for src_file in "${SRCS[@]}"
	do
		if [[ "${src_file}" == './*.c' ]]; then
			echo "what"
			continue
		fi

		src_name=$(basename "${src_file}")

		# From https://stackoverflow.com/questions/965053/extract-filename-and-extension-in-bash
		extn="${src_name##*.}"
		name="${src_name%.*}"

		obj_file="${BUILD_DIR}/${name}.o"

		if [[ ${extn} == 'c' ]]; then
			echo "c: ${src_name}"
			${CC} ${CFLAGS[@]} ${EXTRA_CFLAGS} "-DIS_AP=${IS_AP}" -DPOST_BOOT_ENABLED="$POST_BOOT_ENABLED" -DPOST_BOOT="${POST_BOOT_CODE//\'/}" -o ${obj_file} ${src_file}
		elif [[ ${extn} == 'S' ]]; then
			echo "S: ${src_name}"
			${CC} ${AFLAGS[@]} -o ${obj_file} -c ${src_file}
		else
			echo "unknown: ${src_name}"
		fi

		OBJS+=("${obj_file}")
	done

	mv "${BUILD_DIR}/encrypted.o" "${BUILD_DIR}/encrypted-raw.o"
	${LD} -r -T ../common/rename.ld -o "${BUILD_DIR}/encrypted.o" "${BUILD_DIR}/encrypted-raw.o"
	rm "${BUILD_DIR}/encrypted-raw.o"

	${LD} -T ${LINKERFILE}              \
		--entry ${ENTRY}                \
		"${LDFLAGS[@]}"                 \
		-o "${BUILD_DIR}/plaintext.elf" \
		"${OBJS[@]}"
	
	${OBJCOPY} --dump-section .code.encrypted="${BUILD_DIR}/plaintext-code.bin" "${BUILD_DIR}/plaintext.elf"

	PATCH_DIR="${BUILD_DIR}/patches"

	poetry run python generate_secrets.py

	${OBJCOPY} \
		--update-section .code.encrypted="${PATCH_DIR}/encrypted-code.bin" \
		"${BUILD_DIR}/plaintext.elf"                                       \
		"${BUILD_DIR}/${PROJECT}.elf"
	
	${OBJCOPY} -O binary "${BUILD_DIR}/${PROJECT}.elf" "${BUILD_DIR}/unpatched.bin"

	poetry run python ../common/scripts/patch_bin.py               \
		"${BUILD_DIR}/unpatched.bin" "${BUILD_DIR}/${PROJECT}.bin" \
		${PATCHES}

	if grep -q "ectf{" "${BUILD_DIR}/${PROJECT}.elf"; then
		echo "Plaintext flag detected in output!" >&2
		rm "${BUILD_DIR}/${PROJECT}.bin"
		exit 1
	fi
}

function release() {
	mkdir -p "${BUILD_DIR}"

	# This doesn't do anything lol
}

function debug() {
	mkdir -p "${BUILD_DIR}"

	echo CC = ${CC}
	echo
	echo AS = ${AS}
	echo
	echo LD = ${LD}
	echo
	echo TARGET = ${TARGET}
	echo
	echo BOARD = ${BOARD}
	echo
	echo BUILD_DIR = ${BUILD_DIR}
	echo
	echo SRCS = "${SRCS[@]}"
	#echo
	#echo SRCS_NOPATH = ${SRCS_NOPATH}
	#echo
	#echo OBJS_NOPATH = ${OBJS_NOPATH}
	#echo
	#echo OBJS = ${OBJS}
	#echo
	#echo LIBS = ${LIBS}
	echo
	echo VPATH = "${VPATH[@]}"
	echo
	echo IPATH = "${IPATH[@]}"
	echo
	echo CFLAGS = "${CFLAGS[@]}"
	echo
	echo AFLAGS = "${AFLAGS[@]}"
	echo
	echo LDFLAGS = "${LDFLAGS[@]}"

	################################################################################
	# Add a rule for generating a header file containing compiler definitions
	# that come from the build system and compiler itself.  This generates a
	# "project_defines.h" header file inside the build directory that can be
	# force included by VS Code to improve the intellisense engine.
	touch "${BUILD_DIR}/empty.c"
	touch "${BUILD_DIR}/project_defines.h"
	${CC} -E -P -dD "${BUILD_DIR}/empty.c" "${CFLAGS}" >> "${BUILD_DIR}/project_defines.h"
	rm "${BUILD_DIR}/empty.c"
}

if [[ $1 == "clean" ]] ; then
	clean
elif [[ $1 == "all" ]] ; then
	all
elif [[ $1 == "release" ]] ; then
	release
elif [[ $1 == "debug" ]] ; then
	debug
else
	echo "unknown argument"
	exit 1
fi

exit
