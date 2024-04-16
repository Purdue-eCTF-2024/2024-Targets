
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
	@echo "#ifndef GLOBAL_SECRETS_H" >> global_secrets.h
	@echo "#define GLOBAL_SECRETS_H" >> global_secrets.h
	@echo "#define SECRET_SIZE 16" >> global_secrets.h
	@echo "extern unsigned char shared_secret[SECRET_SIZE+1];" >> global_secrets.h
	@echo "//Needed a structure that can be externed throughout the project so that the signature can be used anywhere." >> global_secrets.h
	@echo "typedef struct {" >> global_secrets.h
	@echo "   size_t message_len;" >> global_secrets.h
	@echo "   unsigned char* signature;" >> global_secrets.h
	@echo "} Signed_Message;" >> global_secrets.h
	@echo "extern Signed_Message signedmessage;" >> global_secrets.h
	@echo "extern int comp_send_status;" >>global_secrets.h
	@echo "extern int comp_receive_status;" >>global_secrets.h
	@echo "#endif" >>global_secrets.h
clean:
	rm -f global_secrets.h
