/**
 * @file "cert_gen.c"
 * @author Kevin Marquis
 * @brief Certificate Generation Script using WolfSSL
 * @date 2024
*/


#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/random.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/ecc.h"

// Configurations
#define DEBUG 0
#define GLOBAL_SECRETS_FILEPATH "../deployment/global_secrets.h"
#define AP_SECRETS_FILEPATH "../application_processor/src/certs.c"
#define COMPONENT_SECRETS_FILEPATH "../component/src/certs.c"

// Global Definitions
#if DEPLOYMENT_CERT_GEN
unsigned char CA_CERT[4096];
unsigned char CA_KEY_DER[4096];
unsigned char CA_SIG_DER[4096];
unsigned char CA_PUB_DER[4096];
int CA_KEY_DER_LEN;
int CA_CERT_SIZE_DER;
int CA_SIG_DER_LEN;
int CA_PUB_DER_LEN;
#else
//Pull CA variables from global_secrets.h when generating device secrets
#include "../../deployment/global_secrets.h"
extern const unsigned char CA_CERT[];
extern const unsigned char CA_KEY_DER[];
extern const unsigned char CA_SIG_DER[];
extern const int CA_KEY_DER_LEN;
extern const int CA_CERT_SIZE_DER;
extern const int CA_SIG_DER_LEN;
extern const int CA_PUB_DER_LEN;

unsigned char DEVICE_DER_CERT[4096];
unsigned char DEVICE_DER_KEY[4096];
unsigned char DEVICE_SIG[128];
unsigned char DEVICE_PUB_DER[4096];
int DEVICE_KEY_DER_LEN;
int DEV_DER_CERT_SIGNED_LENGTH;
int DEVICE_SIG_LEN;
int DEVICE_PUB_DER_LEN;
#endif

char error_message[WOLFSSL_MAX_ERROR_SZ];
long e = 65537;


/** @brief Takes in a buffer and prints its values in hexadecimal.
 * 
 *  @param data A pointer to a buffer that shall be printed to stdout,
 *  @param len The length of buffer data.
 * 
 *  @returns None
*/
void print_hex(const unsigned char* data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}


/** @brief Writes a buffer to a file (such that it can be included as a header).
 * 
 *  @param buffer_name A string containing the name of the buffer once written to a file.
 *  @param buffer_size The size of the buffer to be written.
 *  @param buffer A pointer to the buffer that shall be written.
 *  @param outfile_name A string with the path to the file to be written into.
 * 
 *  @returns 0 if successful.
*/
int write_buffer_to_file(char * buffer_name, int buffer_size, byte * buffer, char * outfile_name){
    int ret;
    FILE * outfile = fopen(outfile_name, "a");

    #if DEBUG
    printf("Writing the following lines to file %s:\n", outfile_name);
    printf("\n\nconst unsigned char %s[] = \n{\n\t", buffer_name);
    #endif

    fprintf(outfile, "\n\nconst unsigned char %s[] = \n{\n\t", buffer_name);
    for (int i = 0; i < buffer_size; i++) {
        if (i == buffer_size - 1){
            #if DEBUG
            printf("0x%02X\n};\n", buffer[i]);
            #endif

            fprintf(outfile, "0x%02X\n};\n", buffer[i]);
            break;
        }
        else{
            #if DEBUG
            printf("0x%02X, ", buffer[i]);
            #endif

            fprintf(outfile, "0x%02X, ", buffer[i]);
            if (i % 10 == 9 && i != 0){
                #if DEBUG
                printf("\n\t");
                #endif

                fprintf(outfile, "\n\t");

            }
        }
    }

    ret = fclose(outfile);
    return ret;
}


/** @brief Writes an integer into a file (i.e. a header file) as a variable.
 * 
 *  @param int_name A string containing the desired name of the integer in the file.
 *  @param int_out The integer that is to be written to the file.
 *  @param outfile_name A string containing the path to the file to be written to.
 * 
 *  @returns 0 if successful.
*/
int write_int_to_file(char * int_name, int int_out, char * outfile_name){
    int ret;
    FILE * outfile = fopen(outfile_name, "a");

    #if DEBUG
    printf("Writing the following lines to file %s:\n", outfile_name);
    printf("\n\nconst unsigned byte %s = %d;\n", int_name, int_out);
    #endif

    fprintf(outfile, "\nconst int %s = %d;\n", int_name, int_out);

    ret = fclose(outfile);
    return ret;
}

int write_str_to_file(char * to_write, char * outfile_name){
    int ret;
    FILE * outfile = fopen(outfile_name, "a");

    #if DEBUG
    printf("Writing the following lines to file %s:\n", outfile_name);
    printf("\n%s\n", to_write);
    #endif

    fprintf(outfile, "\n%s\n", to_write);

    ret = fclose(outfile);
    return ret;
}

/** @brief Generates RSA Keys and Certificates for a Deployment, AP, or Component.
 * 
 *  @param (Optional) When compiled for Device Secret Generation, provide 1 if AP, 0 if Component.
 * 
*/
int main(int argc, char *argv[]){
    #if !DEPLOYMENT_CERT_GEN
    if (argc != 2){
        fprintf(stderr, "ERROR: Incorrect number of arguments\n");
        printf("Usage: cert_gen AP?\n");
        exit(1);
    }
    #endif

    #if !DEPLOYMENT_CERT_GEN
    int AP_OR_COMP = 0;
    char DEVICE_SECRETS_FILE_PATH[1024]; //excessively large filepath length
    sscanf(argv[1], "%d", &AP_OR_COMP);
    if (AP_OR_COMP){
        sprintf(DEVICE_SECRETS_FILE_PATH, AP_SECRETS_FILEPATH);
    }
    else{
        sprintf(DEVICE_SECRETS_FILE_PATH, COMPONENT_SECRETS_FILEPATH);
    }
    #endif

    RsaKey CA_KEY;

    #if !DEPLOYMENT_CERT_GEN
    RsaKey DEVICE_KEY;
    ecc_key dev_ecc;
    #endif

    WC_RNG rng;
    int ret = 0;

    #if DEBUG
    ret = wolfSSL_Debugging_ON();
    #endif
    
    ret = wc_InitRng(&rng);
    if (ret != 0){
        printf("Error in initializing RNG, Ret= %d\n", ret);
        wc_ErrorString(ret, error_message);
        fprintf(stderr, "WOLFSSL Error Message: %s", error_message);
        return -1;
    }

    //Initialize RSA Key objects
    ret = wc_InitRsaKey(&CA_KEY, NULL);
    if (ret != 0){
        printf("Error in initializing RSA Key.  Ret= %d\n", ret);
        wc_ErrorString(ret, error_message);
        fprintf(stderr, "WOLFSSL Error Message: %s", error_message);
        return -1;
    }

    #if !DEPLOYMENT_CERT_GEN
    ret = wc_ecc_init(&dev_ecc); 
    if (ret < 0){
        #if DEBUG
        print_error("Failed to initialize device ECC Key.  Returned %d\n", ret);
        #endif
        return -1;
    }
    #endif
    
    //Build RSA Keys
    #if DEPLOYMENT_CERT_GEN
    ret  = wc_MakeRsaKey(&CA_KEY, 1024, 65537, &rng);
    if (ret != 0){
        printf("Error in making RSA key.  Ret=%d\n", ret);
        wc_ErrorString(ret, error_message);
        fprintf(stderr, "WOLFSSL Error Message: %s", error_message);
        return -1;
    }
    #else
    ret = wc_ecc_make_key(&rng, 32, &dev_ecc); // make public/private key pair
    if (ret < 0){
        #if DEBUG
        printf("Error in making RSA key.  Ret=%d\n", ret);
        wc_ErrorString(ret, error_message);
        fprintf(stderr, "WOLFSSL Error Message: %s", error_message);
        #endif
        return -1;
    }
    #endif
    
    #if DEBUG
    printf("RSA Keys Created!\n");
    #endif

    //Format RSA Keys for output
    #if DEPLOYMENT_CERT_GEN
    CA_KEY_DER_LEN = wc_RsaKeyToDer(&CA_KEY, CA_KEY_DER, 4096);
    if (CA_KEY_DER_LEN < 0){
        printf("Error in converting RSA Key. Ret= %d\n", CA_KEY_DER_LEN);
        wc_ErrorString(CA_KEY_DER_LEN, error_message);
        fprintf(stderr, "WOLFSSL Error Message: %s", error_message);
        return -1;
    }

    CA_PUB_DER_LEN = wc_RsaKeyToPublicDer(&CA_KEY, CA_PUB_DER, sizeof(CA_PUB_DER));
    if (CA_PUB_DER_LEN < 0){
        printf("Error in converting CA Public Key to DER format.  Ret = %d\n", CA_PUB_DER_LEN);
        wc_ErrorString(CA_PUB_DER_LEN, error_message);
        fprintf(stderr, "WOLFSSL Error Message: %s", error_message);
        return -1;
    }
    #else
    DEVICE_KEY_DER_LEN = wc_EccKeyToDer(&dev_ecc, DEVICE_DER_KEY, sizeof(DEVICE_DER_KEY));
    if (DEVICE_KEY_DER_LEN < 0){
        printf("Error in converting ECC Key. Ret= %d\n", DEVICE_KEY_DER_LEN);
        wc_ErrorString(DEVICE_KEY_DER_LEN, error_message);
        fprintf(stderr, "WOLFSSL Error Message: %s", error_message);
        return -1;
    }

    DEVICE_PUB_DER_LEN = wc_EccPublicKeyToDer(&dev_ecc, DEVICE_PUB_DER, sizeof(DEVICE_PUB_DER), 1);
    if (DEVICE_PUB_DER_LEN < 0){
        #if DEBUG
        printf("Error in converting device Public Key to DER format.  Ret = %d\n", DEVICE_PUB_DER_LEN);
        wc_ErrorString(DEVICE_PUB_DER_LEN, error_message);
        fprintf(stderr, "WOLFSSL Error Message: %s", error_message);
        #endif
        return -1;
    }
    #endif

    #if DEBUG
    printf("Outputted key!\nDER KEY:\n");
    print_hex(CA_KEY_DER, CA_KEY_DER_LEN);
    #endif

    #if !DEPLOYMENT_CERT_GEN
    //Decode CA Key from Global Secrets
    word32 idx = 0;
    ret = wc_RsaPrivateKeyDecode(CA_KEY_DER, &idx, &CA_KEY, CA_KEY_DER_LEN);
    if (ret != 0){
        printf("Error in decoding CA Key. Ret=%d\n", ret);
        wc_ErrorString(ret, error_message);
        fprintf(stderr, "WOLFSSL Error Message: %s\n", error_message);
        return -1;
    }

    #if DEBUG
    printf("Dev Cert Size: %d\n", dev_der_size);
    printf("Dev Certificate Created!\n");
    #endif

    Sha256         sha256;
    uint8_t DEVICE_PUB_HASH[SHA256_DIGEST_SIZE];

    if (ret == 0)
        ret = wc_InitSha256(&sha256);
    if (ret == 0) {
        ret = wc_Sha256Update(&sha256, DEVICE_PUB_DER, DEVICE_PUB_DER_LEN);
    }
    if (ret == 0)
        ret = wc_Sha256Final(&sha256,  DEVICE_PUB_HASH);

    DEVICE_SIG_LEN = wc_RsaSSL_Sign((byte *) DEVICE_PUB_HASH, SHA256_DIGEST_SIZE, DEVICE_SIG, 128, &CA_KEY, &rng);
    if (DEVICE_SIG_LEN <= 0){
        printf("Failed to sign Device Public Key!\n");
        wc_ErrorString(ret, error_message);
        fprintf(stderr, "WOLFSSL Error Message: %s\n", error_message);
        return -1;
    }

    #endif // !DEPLOYMENT_CERT_GEN

    //Write to files:
    #if DEPLOYMENT_CERT_GEN
    
    #if DEBUG
    printf("Writing CA Key to Global Secrets.h...\n");
    #endif

    ret = write_buffer_to_file("CA_KEY_DER", CA_KEY_DER_LEN, CA_KEY_DER, GLOBAL_SECRETS_FILEPATH);
    if (ret){
        fprintf(stderr, "Error writing CA Key to global secrets!\n");
        return -1;
    }

    ret = write_int_to_file("CA_KEY_DER_LEN", CA_KEY_DER_LEN, GLOBAL_SECRETS_FILEPATH);
    if (ret){
        fprintf(stderr, "Error writing CA_CERT_SIZE_DER to global secrets!\n");
        return -1;
    }

    #if DEBUG
    printf("Writing CA Certificate to Global Secrets.h...\n")
    #endif
    ret = write_buffer_to_file("CA_PUB_DER", CA_PUB_DER_LEN, CA_PUB_DER, GLOBAL_SECRETS_FILEPATH);
    if (ret){
        fprintf(stderr, "Error writing CA Certificate to global secrets!\n");
        return -1;
    }

    ret = write_int_to_file("CA_PUB_DER_LEN", CA_PUB_DER_LEN, GLOBAL_SECRETS_FILEPATH);
    if (ret){
        fprintf(stderr, "Error writing CA_CERT_SIZE_DER to global secrets!\n");
        return -1;
    }

    #else
    ret = write_str_to_file("#include \"certs.h\"\n\n", DEVICE_SECRETS_FILE_PATH);
    if (ret){
        fprintf(stderr, "Error writing Preprocessor Directive to certs.c\n");
        return -1;
    }

    ret = write_buffer_to_file("DEVICE_PUB_DER", DEVICE_PUB_DER_LEN, DEVICE_PUB_DER, DEVICE_SECRETS_FILE_PATH);
    if (ret){
        fprintf(stderr, "Error writing Device Public Key to certs.c\n");
        return -1;
    }
    
    ret = write_int_to_file("DEVICE_PUB_DER_LEN", DEVICE_PUB_DER_LEN, DEVICE_SECRETS_FILE_PATH);
    if (ret){
        fprintf(stderr, "Error writing DEVICE_PUB_DER_LEN to certs.c\n");
        return -1;
    }

    ret = write_buffer_to_file("DEVICE_SIG", DEVICE_SIG_LEN, DEVICE_SIG, DEVICE_SECRETS_FILE_PATH);
    if (ret){
        fprintf(stderr, "Error writing Device Public Key Signature to certs.c\n");
        return -1;
    }
    
    ret = write_int_to_file("DEVICE_SIG_LEN", DEVICE_SIG_LEN, DEVICE_SECRETS_FILE_PATH);
    if (ret){
        fprintf(stderr, "Error writing DEVICE_SIG_LEN to certs.c\n");
        return -1;
    }

    ret = write_buffer_to_file("DEVICE_KEY", DEVICE_KEY_DER_LEN, DEVICE_DER_KEY, DEVICE_SECRETS_FILE_PATH);
    if (ret){
        fprintf(stderr, "Error writing Device Key to certs.c\n");
        return -1;
    }

    ret = write_int_to_file("DEVICE_KEY_DER_LEN", DEVICE_KEY_DER_LEN, DEVICE_SECRETS_FILE_PATH);
    if (ret){
        fprintf(stderr, "Error writing DEVICE_KEY_DER_LEN to certs.c\n");
        return -1;
    }

    ret = write_buffer_to_file("CA_PUB_DER", CA_PUB_DER_LEN, CA_PUB_DER, DEVICE_SECRETS_FILE_PATH);
    if (ret){
        fprintf(stderr, "Error writing CA Certificate to certs.c\n");
        return -1;
    }

    ret = write_int_to_file("CA_PUB_DER_LEN", CA_PUB_DER_LEN, DEVICE_SECRETS_FILE_PATH);
    if (ret){
        fprintf(stderr, "Error writing CA_CERT_SIZE_DER to certs.c\n");
        return -1;
    }

    #endif // DEPLOYMENT_CERT_GEN

    printf("Success!\n");

    
    wc_FreeRsaKey(&CA_KEY);
    #if !DEPLOYMENT_CERT_GEN
    wc_ecc_free(&dev_ecc);
    #endif

    return 0;
}
