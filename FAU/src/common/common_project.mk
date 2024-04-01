# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

#MXC_OPTIMIZE_CFLAGS = -Og
# ^ For example, you can uncomment this line to 
# optimize the project for debugging

# **********************************************************

# Add your config here!

# This example is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

IPATH+=../deployment
IPATH+=inc/
VPATH+=src/

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ****************** eCTF Crypto Example *******************
# Uncomment the commented lines below and comment the disable
# lines to enable the eCTF Crypto Example.
# WolfSSL must be included in this directory as wolfssl/
# WolfSSL can be downloaded from: https://www.wolfssl.com/download/

# Disable Crypto Example
CRYPTO_EXAMPLE=0

DEBUG = 0

############## BEGIN WOLFSSL CONFIGURATION ############## 
# wolfssl Flags
# https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html#building-with-gcc-arm
# https://www.wolfssl.com/how-do-i-manage-the-build-configuration-of-wolfssl/
# PROJ_CFLAGS += -DWOLFSSL_USER_SETTINGS -DHAVE_PK_CALLBACKS \
#                -DWOLFSSL_USER_IO -DNO_WRITEV -DTIME_T_NOT_64BIT \
# 			   -DWOLFSSL_LOAD_FLAG_DATE_ERR_OKAY 

PROJ_CFLAGS += -DWOLFSSL_USER_SETTINGS -DTIME_T_NOT_64BIT

############## STACK PROTECTION AND SECURITY FLAGS ##############
# -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -Werror=format-security
#  ^THANKS CMU
#  https://gcc.gnu.org/onlinedocs/gcc/ARM-Options.html
# -mstack-protector-guard=global <-- replace global with specifics? 
#  "Supported locations are 'global' for a global canary or 'sysreg' for a canary in an appropriate system register."

PROJ_CFLAGS += -D_FORTIFY_SOURCE=3 -fstack-protector-all -mstack-protector-guard=global -Wformat -Wformat-security -Werror=format-security

#-DLARGE_STATIC_BUFFERS

# Enable "DEBUG" symbol in .c files
ifeq ($(DEBUG), 1)
PROJ_CFLAGS += -DDEBUG
endif

# Use client or server depending on the device
ifeq ($(DEVICE), AP)

USER_SETTINGS_DIR = $(abspath ../common/wolfssl/IDE/MAX78000_Client/Header)
PROJ_LDFLAGS += -L$(abspath ../common/wolfssl/IDE/MAX78000_Client/Build/)

else ifeq ($(DEVICE), COMPONENT)

USER_SETTINGS_DIR = $(abspath ../common/wolfssl/IDE/MAX78000_Server/Header)
PROJ_LDFLAGS += -L$(abspath ../common/wolfssl/IDE/MAX78000_Server/Build/)

else
$(error ERROR: common_project.mk: Variable DEVICE with value $(DEVICE) is not valid!)
endif

IPATH += $(USER_SETTINGS_DIR)
IPATH += $(abspath ../common/wolfssl)
IPATH += $(abspath ../common/)
IPATH += $(abspath ../common/inc/)
VPATH += $(abspath ../common/src/)
PROJ_LIBS += :libwolfssl.a
############## END WOLFSSL CONFIGURATION ############## 

# Prints a variable's value to tty
# example usage: 'make print-PROJ_LDFLAGS'
print-%  : ; @echo $* = $($*)
