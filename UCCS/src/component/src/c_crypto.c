#include"../../application_processor/inc/simple_crypto.h"

#define SUCCESS_RETURN 0
#define ERROR_RETURN -1
#define MAX_LEN 64
// variable to store signature
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "global_secrets.h"

int sign_message(size_t message_len, unsigned char* signature){
    if (signature == NULL || shared_secret[0] == '\0') {
        return ERROR_RETURN;
    }
    size_t max_signature_len = message_len + sizeof(shared_secret);
    if (max_signature_len > MAX_LEN) {
        return ERROR_RETURN; // Error code for exceeding maximum length
    }
    // memcpy(signature, shared_secret, message_len);
    memcpy(signature, shared_secret, sizeof(shared_secret));
    return SUCCESS_RETURN;
}
    // Function to verify the signature of a message
int verify_signature(size_t message_len, unsigned char* signature) {
    if(signature == NULL || shared_secret[0 ]== '\0'){
        return 2;
    }
    unsigned char expected_signature[SIGNATURE_SIZE];
    if(sign_message(message_len, expected_signature) !=0 ){
        return 5;
    }
    int m = memcmp(signature, expected_signature, sizeof(shared_secret));
    if (m!= 0) {
        return m;
    }
    return SUCCESS_RETURN;
}