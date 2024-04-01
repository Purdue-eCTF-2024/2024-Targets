
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

PWD := $(shell echo $$PWD)

all:
	chmod +x ssl_gen_ca.sh
	./ssl_gen_ca.sh

clean:
	rm -rf certs
