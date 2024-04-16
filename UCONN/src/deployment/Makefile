
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
	cd ../secret_generation && make clean && make DEPLOYMENT_GEN=1 && ./cert_gen && make clean && cd -
	cd ../secret_generation && make DEPLOYMENT_GEN=0 && cd -

clean:
	rm -f global_secrets.h
	cd ../secret_generation && make clean && cd -
