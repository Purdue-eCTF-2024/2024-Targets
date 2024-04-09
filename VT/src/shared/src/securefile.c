/*
* securefile.c
* @brief This file contains the functions for the secure file, including signing and verifying the key
* @date 2024
* @note This file is part of the MITRE's 2024 Embedded System CTF (eCTF).
*/
/*********************************************************************************************************/
#include "securefile.h"

// Function to sign the key
uint8_t * sign_key(char * privateKey, uint8_t * hash_message, const struct uECC_Curve_t * curve) {
    uint8_t *signature = (uint8_t *)malloc(64 * sizeof(uint8_t));                  
    uint8_t Private_Key[32];                                
    for (int i = 0; i < 64; i=i+2) {                        
        char hex[3];                                        
        strncpy(hex, privateKey + i, 2);  
        hex[2] = '\0';                  
        Private_Key[i/2] = (uint8_t)strtol(hex, 0, 16);     
    }
    int result = uECC_sign(Private_Key, hash_message, sizeof(hash_message), signature, curve);
    if (result == 1) {
        //print_error("Key signing failed\n");
        return signature;
    }
    else {
        //print_success("Key signed\n");
        //print64_m((char *)signature);
        free(signature);
        return NULL;
    }
}

// Function to verify the key
int verify_key(char * public_x, char * public_y, uint8_t * rec_hash, uint8_t * rec_signature, const struct uECC_Curve_t * curve) {
    //uint8_t public_key_x[64];
    //uint8_t public_key_y[64];    
    //strcpy((char *)(public_key_x), public_x);
    //strcpy((char *)(public_key_y), public_y);

    // get the public key : x and y concatenated
    uint8_t public_key[64];
    for (int i = 0; i < 64; i=i+2) {
        char hex[3];
        strncpy(hex, public_x + i, 2);
        hex[2] = '\0';
        public_key[i/2] = (uint8_t)strtol(hex, 0, 16);
    }
    for (int i = 0; i < 64; i=i+2) {
        char hex[3];
        strncpy(hex, public_y + i, 2);
        hex[2] = '\0';
        public_key[(i/2)+32] = (uint8_t)strtol(hex, 0, 16);
    }

    int verify_result = uECC_verify(public_key, rec_hash, sizeof(rec_hash), rec_signature, curve);
    if (verify_result == 1) {
        //print_success("Key verified\n");
        return SUCCESS_RETURN;
    }
    else {
        //print_error("Key verification failed\n");
        MXC_Delay(1000);
        return ERROR_RETURN;
    }
}
/*********************************************************************************************************/