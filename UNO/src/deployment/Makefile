
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))
CC=gcc
CFLAGS=$(shell pkg-config --cflags wolfssl)
LDFLAGS=$(shell pkg-config --libs wolfssl)

all: global_secrets.h

keygen: keygen.c
	$(CC) keygen.c $(CFLAGS) $(LDFLAGS) -o keygen

global_secrets.h: keygen
	./keygen

clean:
	rm -f global_secrets.h keygen