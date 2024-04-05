
# function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

all:
#	echo "#define SECRET 1234" > global_secrets.h
	{  \
	pass1=$$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12; echo);   \
	pass1md5=($$(echo -n "$$pass1" | md5sum));   \
	pass2=$$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12; echo);   \
	pass2md5=($$(echo -n "$$pass2" | md5sum));   \
	pass3=$$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12; echo);   \
	pass3md5=($$(echo -n "$$pass3" | md5sum));   \
	echo "#define PASS1 \"$$pass1\"" > global_secrets.h;   \
	echo "#define PASS2 \"$$pass2\"" >> global_secrets.h;   \
	echo "#define PASS3 \"$$pass3\"" >> global_secrets.h;   \
	echo "#define PASS1MD5 \"$$pass1md5\"" >> global_secrets.h;   \
	echo "#define PASS2MD5 \"$$pass2md5\"" >> global_secrets.h;   \
	echo "#define PASS3MD5 \"$$pass3md5\"" >> global_secrets.h;   \
	}

clean:
	rm -f global_secrets.h
	rm -f global_secrets.h
