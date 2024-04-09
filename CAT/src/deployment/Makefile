
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))	
		
all:
	echo "#define SECRET 1234" > global_secrets.h
clean:
	rm -f global_secrets.h
	rm -f ../component/inc/global_secrets.h
	rm -rf ../build
	rm -rf ../application_processor/inc/ectf_params.h
	rm -rf ../application_processor/build ../component/build
	rm -rf ../walkthrough/colombehsn.pem
	rm -rf ../application_processor/src/public.pem ../application_processor/src/signature.bin
	rm -rf ../component/inc/ectf_params.h
	
	