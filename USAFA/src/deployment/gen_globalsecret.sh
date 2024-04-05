#!/bin/bash

# NOT USED ANYMORE USE global_secret.sh

randomValue=$((RANDOM % 1000000000))
echo "#define verificationKey ${randomValue}" > global_secrets.h

