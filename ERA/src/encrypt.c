#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include "component/inc/aes.h"
#include "component/src/aes.c"
#include "deployment/global_secrets.h"

#define BLOCK_SIZE 64
char* string_to_hex(const char* input) {
    size_t len = strlen(input);
    char* hex_string = (char*)malloc(2 * len + 1); // Each character in the input string corresponds to two hex characters, plus one for the null terminator

    if (hex_string == NULL) {
        // Handle memory allocation failure
        return NULL;
    }

    for (size_t i = 0; i < len; i++) {
        sprintf(hex_string + 2 * i, "%02X", (unsigned char)input[i]); // Convert each character to its hexadecimal representation
    }

    // Convert hex string to lowercase
    for (size_t i = 0; i < 2 * len; i++) {
        hex_string[i] = tolower(hex_string[i]);
    }

    hex_string[2 * len] = '\0'; // Null-terminate the hexadecimal string
    return hex_string;
}
char* extract_key(const char* secret) {
    char* key = malloc(17); 
    
    if (strlen(secret) >= 16) {
        for (int i = 0; i < 16; i++) {
            key[i] = secret[i];
        }
    } else {
        for (int i = 0; i < strlen(secret); i++) {
            key[i] = secret[i];
        }

        for (int i = strlen(secret); i < 16; i++) {
            key[i] = '.';
        }
    }
    
    key[16] = '\0'; 
    return key;
}

int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void bytes_to_hex_string(uint8_t* bytes, size_t num_bytes, char* hex_str) {
    for (size_t i = 0; i < num_bytes; i++) {
        sprintf(&hex_str[i * 2], "%02x", bytes[i]);
    }
    hex_str[num_bytes * 2] = '\0'; // Null-terminate the string
}

void hex_string_to_bytes(char* hex_str, uint8_t* bytes) {
    size_t num_bytes = strlen(hex_str) / 2;
    for (size_t i = 0; i < num_bytes; i++) {
        bytes[i] = hex_char_to_int(hex_str[i * 2]) * 16 + hex_char_to_int(hex_str[i * 2 + 1]);
    }
}

// Function to encrypt data and update the header file
void update_header() {
    FILE *header_file = fopen("inc/ectf_params.h", "r+");
    if (header_file == NULL) {
        perror("Error opening header file");
        return;
    }

    uint8_t current_location[256] = {0};
    uint8_t current_date[256] = {0};
    uint8_t current_customer[256] = {0}; // Fixed size to match others
    char hex_location[513] = {0}; // Size adjusted for hex string
    char hex_date[513] = {0}; // Size adjusted for hex string
    char hex_customer[513] = {0}; // Size adjusted for hex string

    char line[512];
    while (fgets(line, sizeof(line), header_file)) {
        if (strstr(line, "#define ATTESTATION_LOC") != NULL) {
            sscanf(line, "#define ATTESTATION_LOC \"%[^\"]\"", current_location);
        } else if (strstr(line, "#define ATTESTATION_DATE") != NULL) {
            sscanf(line, "#define ATTESTATION_DATE \"%[^\"]\"", current_date);
        } else if (strstr(line, "#define ATTESTATION_CUSTOMER") != NULL) {
            sscanf(line, "#define ATTESTATION_CUSTOMER \"%[^\"]\"", current_customer);
        }
    }
    fclose(header_file); // Close to reopen later for writing

    // Generate a random key
    char* key=(char*)malloc(17);
    key=extract_key(KEY) ;
    char* hex_key=(char*)malloc(33);    
    hex_key=string_to_hex(key);
    uint8_t last_key[16];
    hex_string_to_bytes(hex_key,last_key);

    struct AES_ctx ctx;
    AES_init_ctx(&ctx, last_key);

    // Encrypt data and convert to hex strings
    AES_ECB_encrypt(&ctx, current_location);
    bytes_to_hex_string(current_location, BLOCK_SIZE, hex_location);

    AES_ECB_encrypt(&ctx, current_date);
    bytes_to_hex_string(current_date, BLOCK_SIZE, hex_date);

    AES_ECB_encrypt(&ctx, current_customer);
    bytes_to_hex_string(current_customer, BLOCK_SIZE, hex_customer);

    // Reopen the header file for writing
    header_file = fopen("inc/ectf_params.h", "r+");
    if (header_file == NULL) {
        perror("Error reopening header file");
        return;
    }
    
    FILE *temp_file = tmpfile();
     while (fgets(line, sizeof(line), header_file) != NULL) {
        if (strstr(line, "#define ATTESTATION_LOC") != NULL) {
            fprintf(temp_file, "#define ATTESTATION_LOC \"%s\"\n", hex_location);
        } else if (strstr(line, "#define ATTESTATION_DATE") != NULL) {
            fprintf(temp_file, "#define ATTESTATION_DATE \"%s\"\n", hex_date);
        } else if (strstr(line, "#define ATTESTATION_CUSTOMER") != NULL) {
            fprintf(temp_file, "#define ATTESTATION_CUSTOMER \"%s\"\n", hex_customer);
        } else {
            // Write the line as is
            fputs(line, temp_file);
        }
    }
    
    //fclose(temp_file); 
    header_file = fopen("inc/ectf_params.h", "w");


    rewind(temp_file); // Go back to the start of the temp_file
while (fgets(line, sizeof(line), temp_file)) {
    fputs(line, header_file); // Write each line to the original file
}

// Clean up
fclose(header_file);
fclose(temp_file);

}

int main() {
    update_header();
    return 0;
}
