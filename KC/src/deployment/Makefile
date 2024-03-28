
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))
	int1 = $(shell python -c 'from random import randint; print(randint(0,255));')
all:
	
	echo "const uint8_t secret[] = {$(int1),$(int1),$(int1),$(int1),$(int1),$(int1),\
	$(int1),$(int1),$(int1),$(int1),$(int1),$(int1),$(int1),$(int1),$(int1),$(int1)};" > global_secrets.h

clean:
	rm -f global_secrets.h
