
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
	# echo "#define SECRET 1234" > global_secrets.h
	# echo "#define HASH_SECRET 2468102468102468" >> global_secrets.h
	# echo "#define FIXED_LENGTH 10" >> global_secrets.h
	# echo "#define verificationKey 13269" >> global_secrets.h
	# echo "#define FLASH_ADDR (MXC_FLASH_MEM_BASE + ${random_numberTwo}*MXC_FLASH_PAGE_SIZE)" >> global_secrets.h
	# echo "#define FLASH_MAGIC 0xDEADBEEF" >> global_secrets.h	
	./global_secret.sh

clean:
	rm -f global_secrets.h
