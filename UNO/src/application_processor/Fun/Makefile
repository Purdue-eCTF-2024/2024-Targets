
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



all: keygen keygen1
	./sanitizePins
	./SanTok
	
keygen: sanitizePins.c
	$(CC) sanitizePins.c $(CFLAGS) $(LDFLAGS) -o sanitizePins

keygen1: SanTok.c
	$(CC) SanTok.c $(CFLAGS) $(LDFLAGS) -o SanTok

clean:
	rm -f sanitizePins
	rm -f SanTok
	
