#!/bin/bash

if [ ! -d "certs" ]; then
    mkdir "certs"
fi

# Clean up
rm -f certs/*.key
# rm -f certs/*.csr
rm -f certs/*.pem

# Generate root CA private key
# openssl genpkey -algorithm ed25519 -out certs/rootCA.key
# openssl ecparam -name secp256k1 -genkey -noout -out certs/rootCA.key
openssl ecparam -genkey -out certs/rootCA.key -name prime256v1

# Generate the root certificate (the host computer)
openssl req -x509 -new -nodes -config openssl_ca.conf -extensions ca_extensions -set_serial 20 -key certs/rootCA.key -days 1024 -out certs/rootCA.pem
