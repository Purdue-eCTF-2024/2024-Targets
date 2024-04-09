
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



all: keygen
	./encryptParams
	
keygen: encryptParams.c
	$(CC) encryptParams.c $(CFLAGS) $(LDFLAGS) -o encryptParams

clean:
	rm -f encryptParams
	
#ifneq ("$(wildcard $(PATH_TO_FILE))","")
 #   FILE_EXISTS = 1
#else
  #  FILE_EXISTS = 0
#endif