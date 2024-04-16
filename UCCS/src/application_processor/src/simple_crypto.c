#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include "simple_crypto.h"
#include "ectf_params.h"
#include <stdint.h>
#include "global_secrets.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
//Macros
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1
#define MAX_LEN 64
// variable to store signature
int pad_pkcs7(const char *data, int data_len, uint8_t *padded_data,
              int block_size) {
    int padded_len = block_size * ((data_len + block_size - 1) / block_size); // Calculate the padded length
    int padding_bytes = padded_len - data_len; // Calculate the number of padding bytes to add
    memcpy(padded_data, data, data_len); // Copy the original data
    memset(padded_data + data_len, padding_bytes, padding_bytes); // Add padding bytes
    return padded_len; // Return the padded length
}
// Function to generate a random key
void generate_key(uint8_t *key) {
    WC_RNG rng;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, key, KEY_SIZE);
    wc_FreeRng(&rng);
    // Failed to generate random key
    wc_FreeRng(&rng);
}

// Function to generate a random initialization vector (IV)
void generate_random_iv(uint8_t *iv) {
    WC_RNG rng;
    wc_InitRng(&rng);
    // Failed to initialize random number generator

    wc_RNG_GenerateBlock(&rng, iv, KEY_SIZE);
    wc_FreeRng(&rng);
}

// Function to encrypt data using AES-256 in CBC mode
int encrypt_n(const char *pin, int pin_len, uint8_t *encrypted_pin, const uint8_t *key, uint8_t *iv) {
    uint8_t padded_pin[BLOCK_SIZE];
    int padded_len = pad_pkcs7(pin, pin_len, padded_pin, BLOCK_SIZE);
    Aes enc;
    if (wc_AesSetKey(&enc, key, KEY_SIZE, iv, AES_ENCRYPTION) != 0) {
        return ERROR_RETURN;
    }
    if (wc_AesCbcEncrypt(&enc, encrypted_pin, padded_pin, padded_len) != 0) {
        return ERROR_RETURN;
    }
    return SUCCESS_RETURN;
}

// Function to compare two encrypted PINs
int compare_pins(const uint8_t *encrypted_pin1, const uint8_t *encrypted_pin2) {
    // Compare the encrypted PINs byte by byte
    for (int i = 0; i < BLOCK_SIZE; i++) {
        if (encrypted_pin1[i] != encrypted_pin2[i]) {
            return ERROR_RETURN; // PINs don't match
        }
    }
    return SUCCESS_RETURN; // PINs match
}

void bytes_to_hex(const uint8_t *bytes, int len, char *hex_str) {
    for (int i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
}

void gen_salt(char *salt){
    WC_RNG rng;

    wc_InitRng(&rng);
    // Generate random salt
    wc_RNG_GenerateBlock(&rng, (uint8_t *)salt, SALT_LEN);

    wc_FreeRng(&rng);
}

//for commss

//Function to generate the secret for comms
void generate_shared_seecret(unsigned char *key,size_t key_len){
    srand(rand());
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+{}[]|;:<>,.?/";
    const size_t charset_len = sizeof(charset) - 1;
    for(size_t i = 0; i < key_len; i++){
        key[i] = charset[rand() % charset_len];
    }
}
// Function to sign a message
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