
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
	pip install ecdsa
	poetry run python3 generate_key.py

clean:
	rm -f global_secrets.h
