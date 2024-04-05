#!/bin/bash

random_number=$((RANDOM % 100000000))
random_numberTwo=$((RANDOM % 41 + 23))

echo "#define verificationKey ${random_number}" > global_secrets.h

## SR 5
echo "#define SECRET 1234" >> global_secrets.h

random_numberHash1=$(shuf -i 0-4294967295 -n 1)  ## Random number for uint32
random_numberHash2=$(shuf -i 0-4294967295 -n 1)  ## Random number for uint32
random_numberHash3=$(shuf -i 0-4294967295 -n 1)  ## Random number for uint32
random_numberHash4=$(shuf -i 0-4294967295 -n 1)  ## Random number for uint32

echo "#define HASH_SECRET1 ${random_numberHash1}" >> global_secrets.h
echo "#define HASH_SECRET2 ${random_numberHash2}" >> global_secrets.h
echo "#define HASH_SECRET3 ${random_numberHash3}" >> global_secrets.h
echo "#define HASH_SECRET4 ${random_numberHash4}" >> global_secrets.h

echo "#define FIXED_LENGTH 10" >> global_secrets.h

## script needs to address the location of flash memory without overwritting information about the flash
## before the flash was overwritting the bootloder so we weren't even able to reset the boards
## find the location in which the flash orginates and fluctuates when storoing code into the flash
echo "#define FLASH_ADDR (MXC_FLASH_MEM_BASE + ${random_numberTwo}*MXC_FLASH_PAGE_SIZE)" >> global_secrets.h
echo "#define FLASH_MAGIC 0xDEADBEEF" >> global_secrets.h

## key for SR 5 for encrypting I2C message
random_char=$(LC_CTYPE=C tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c1) ## random char, ensure a single byte character

echo "#define MESSAGE_KEY '${random_char}'" >> global_secrets.h