CC=gcc
CFLAGS=-Iwolfssl -Iinc -Wall -DWOLFSSL_USER_SETTINGS -DWOLFSSL_CERT_GEN -DWOLFSSL_KEY_GEN -g
LDFLAGS=

TARGET=cert_gen
SRC=src/cert_gen.c

# WolfSSL source directory
WOLFSSL_DIR = wolfssl/src
WOLFCRYPT_DIR = wolfssl/wolfcrypt/src

# Find all source files in WolfSSL directory recursively
WOLFSSL_SRC := $(shell find $(WOLFSSL_DIR) -name '*.c')
WOLFCRYPT_SRC := $(shell find $(WOLFCRYPT_DIR) -name '*.c')

# Object files
OBJ=$(SRC:.c=.o) $(WOLFSSL_SRC:.c=.o) $(WOLFCRYPT_SRC:.c=.o)

ifeq ($(DEPLOYMENT_GEN), 1)
	CFLAGS += -DDEPLOYMENT_CERT_GEN=1
else
	CFLAGS += -DDEPLOYMENT_CERT_GEN=0
endif

# Default target
all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean