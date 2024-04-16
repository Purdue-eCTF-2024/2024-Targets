#include <wolfssl/wolfcrypt/settings.h>
#include<wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include<wolfssl/wolfcrypt/random.h>
#include<wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/types.h>
#include "global_secrets.h"

//Definitions
#define SIGNATURE_SIZE 16
#define KEY_SIZE 32
#define BLOCK_SIZE 32
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1
#define SALT_LEN 13


int pad_pkcs7(const char *data, int data_len, uint8_t *padded_data,
              int block_size);

void generate_key(uint8_t *key);

void generate_random_iv(uint8_t *iv);

int encrypt_n(const char *pin, int pin_len, uint8_t *encrypted_pin,
             const uint8_t *key, uint8_t *iv);

int compare_pins(const uint8_t *encrypted_pin, const uint8_t *encrypted_pin1);

void gen_salt(char *salt);

void bytes_to_hex(const uint8_t *bytes, int len, char *hex_str);

void generate_shared_seecret(unsigned char *key, size_t key_len);

int sign_message(size_t message_len, unsigned char* signature);

int verify_signature(size_t message_len,
                     unsigned char *signature);