
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
	poetry run pip install pymonocypher==3.1.3.2
	poetry run python global_secrets.py

clean:
	rm -f global_secrets.json
