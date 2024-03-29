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

IPATH+=../deployment
IPATH+=inc/
IPATH+=../custom_lib/inc
VPATH+=src/
VPATH+=../custom_lib/src

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
# There is no additional functionality as in the application_processor
# but this will set up compilation and linking for WolfSSL

# Disable Crypto Example
#CRYPTO_EXAMPLE=0

DEBUG = 0

# Enable Crypto Example
CRYPTO_EXAMPLE=1
PROJ_CFLAGS += -DWOLFSSL_SHA3
PROJ_CFLAGS += -DTFM_TIMING_RESISTANT
PROJ_CFLAGS += -DECC_TIMING_RESISTANT
PROJ_CFLAGS += -DWC_RSA_BLINDING
PROJ_CFLAGS += -DSINGLE_THREADED
PROJ_CFLAGS += -DWOLFCRYPT_ONLY
# Disable WolfSSL flags
PROJ_CFLAGS += -DNO_INLINE
PROJ_CFLAGS += -DNO_DH
PROJ_CFLAGS += -DNO_MD2
PROJ_CFLAGS += -DNO_WOLFSSL_CLIENT
PROJ_CFLAGS += -DNO_WOLFSSL_SERVER
PROJ_CFLAGS += -DNO_DES3
PROJ_CFLAGS += -DNO_DSA
PROJ_CFLAGS += -DNO_TLS
PROJ_CFLAGS += -DNO_SHA
PROJ_CFLAGS += -DNO_ERROR_STRINGS
PROJ_CFLAGS += -DNO_SHA256
PROJ_CFLAGS += -DNO_OLD_TLS
PROJ_CFLAGS += -DNO_PWDBASED
PROJ_CFLAGS += -DWOLFSSL_SP_NO_256
PROJ_CFLAGS += -DWOLFSSL_SP_NO_3072
PROJ_CFLAGS += -DWOLFSSL_SP_NO_2048
PROJ_CFLAGS += -DNO_ASN
PROJ_CFLAGS += -DNO_RESUME_SUITE_CHECK
PROJ_CFLAGS += -DWOLFSSL_NO_SIGALG
PROJ_CFLAGS += -DNO_DEV_URANDOM
PROJ_CFLAGS += -DWC_NO_RSA_OAEP
PROJ_CFLAGS += -DNO_RSA
PROJ_CFLAGS += -DNO_SESSION_CACHE
PROJ_CFLAGS += -DNO_RC4
PROJ_CFLAGS += -DNO_PSK
PROJ_CFLAGS += -DNO_MD5
PROJ_CFLAGS += -DNO_MD4
PROJ_CFLAGS += -DWC_NO_HASHDRBG
PROJ_CFLAGS += -DWC_NO_RNG
PROJ_CFLAGS += -DNO_KDF
PROJ_CFLAGS += -DNO_FILESYSTEM
PROJ_CFLAGS += -fstack-protector-all


override .DEFAULT_GOAL := custom_all 

custom_all: add_nop_slides all remove_nop_slides 

add_nop_slides:
	python3 ../scripts/nop_slide.py ../custom_lib add
	python3 ../scripts/nop_slide.py ../component add
remove_nop_slides:
	python3 ../scripts/nop_slide.py ../custom_lib remove
	python3 ../scripts/nop_slide.py ../component remove
# ectf_params_encrypt:
# 	python3 ./component/scripts/encrypt_pin.py ./component/inc/ectf_params.h ./component/inc/ectf_params_encrypted.h ./deployment/global_secret.h