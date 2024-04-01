#!/bin/bash

COMMON=../../../common
DEPL=../../../deployment

cd $1

if [ ! -d "./build/certs" ]; then
    mkdir -p "./build/certs"
fi

cd "./build/certs"

# Clean up
rm -f *.key
rm -f *.csr
rm -f *.pem

# Generate device key
# openssl genpkey -algorithm ed25519 -out device.key
openssl ecparam -genkey -out device.key -name prime256v1

# Generate certificate signing requests (CSRs) for all devices
openssl req -new -config ${COMMON}/openssl/openssl_device.conf -key device.key -out device.csr

# Sign the CSR, creating a certificate
openssl x509 -req \
             -in device.csr \
             -CA ${DEPL}/certs/rootCA.pem \
             -CAkey ${DEPL}/certs/rootCA.key \
             -extfile ${COMMON}/openssl/openssl_device.conf \
             -extensions x509v3_extensions \
             -set_serial 21 \
             -out device.pem \
             -days 365 \
             -sha256

# Verify the certificates
# openssl x509 -in device.pem -text -noout

# Cleanup
rm -f *.csr