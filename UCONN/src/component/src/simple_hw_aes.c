/**
 * @file "simple_hw_aes.c"
 * @author Ben Janis
 * @brief Simplified Hardware Accelerated AES API Implementation
 * @date 2024
 */

#include "simple_hw_aes.h"
#define NO_EXT_INIT 0
#define NO_EXT_SHUTDOWN 0

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts a block of plaintext using built-in hardware accelerated AES.
 * 
 * @param plaintext A pointer to a buffer of length 16B containing the
 *          plaintext to encrypt
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 * 
 * @return 0 on success, other non-zero for other error
 */
int enc_aes_128_block(uint32_t * plaintext, uint32_t * ciphertext, uint8_t * key){
    int ret;
    mxc_aes_req_t req;

    req.length = MXC_AES_SINGLEBLOCK_DATA_LENGTH;
    req.inputData = plaintext;
    req.resultData = ciphertext;
    req.keySize = MXC_AES_128BITS;
    req.encryption = MXC_AES_ENCRYPT_EXT_KEY;

    //May add key masking here

    #if NO_EXT_INIT
    // Power on AES Unit
    // Ideally, do this outside of this function and shutdown when done with encryption.
    ret = MXC_AES_Init();
    if (ret != E_SUCCESS){
        return ret;
    }
    #endif

    MXC_AES_SetKeySize(MXC_AES_128BITS);
    MXC_AES_SetExtKey(key, MXC_AES_128BITS);

    ret = MXC_AES_Encrypt(&req);

    return ret;
}


/** @brief Decrypts a block of ciphertext using a HW Accelerated AES.
 *
 * @param ciphertext A pointer to a buffer, containing 1 block of ciphertext
 *           to decrypt.
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length 16B where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, other non-zero for other error
 */
int dec_aes_128_block(uint32_t * plaintext, uint32_t * ciphertext, uint8_t * key){
    int ret;
    mxc_aes_req_t req;

    req.length = MXC_AES_SINGLEBLOCK_DATA_LENGTH;
    req.inputData = ciphertext;
    req.resultData = plaintext;
    req.keySize = MXC_AES_128BITS;
    req.encryption = MXC_AES_DECRYPT_INT_KEY;  //This macro naming makes absolutely no sense

    //May add key masking here
    MXC_AES_SetKeySize(MXC_AES_128BITS);
    MXC_AES_SetExtKey(key, MXC_AES_128BITS);

    ret = MXC_AES_Decrypt(&req);
    if (ret != E_SUCCESS){
        return ret;
    }

    #if NO_EXT_SHUTDOWN
    // Shutdown AES Unit - Again, ideally do this outside this function
    ret = MXC_AES_Shutdown();
    #endif
}

/** @brief Demonstrates the encryption and decryption of a single block of plaintext.
 *
 * @return  None
 */
void aes_demo(){
    print_info("\n***** AES Example *****\n");   
    int ret = MXC_AES_Init();
    if (ret != E_SUCCESS){
        print_error("Failed to initialize AES!\n");
        return;
    }

    char plaintext[16] = {0};
    char ciphertext[16] = {0};
    char decrypted[16] = {0};
    uint32_t key[16] = {0};  //{0x12345678, 0x12345678, 0x12345678, 0x12345678};

    sprintf(plaintext, "Hello, World!\n");
    sprintf(key, "Encryption_Key!!");

    print_info("Plaintext: %s\n", plaintext);
    print_debug("Encrypting data...\n");

    ret = enc_aes_128_block(plaintext, ciphertext, key);
    if (ret != 0){
        print_error("Encryption Error Occured: %d\n", ret);
    }
    print_info("Ciphertext:\n", ciphertext);
    for (int i = 0; i < 16; i++){
        print_info("%X ", ciphertext[i]);
    }
    print_debug("Decrypting data...\n");
    dec_aes_128_block(decrypted, ciphertext, key);
    if (ret != 0){
        print_error("Decryption Error Occured: %d\n", ret);
    }

    print_info("Decrypted Ciphertext: %s\n", decrypted);

    print_debug("Shutting Down AES...\n");
    ret = MXC_AES_Shutdown();
    if (ret != 0){
        print_error("Failed to shutdown AES: %d\n", ret);
    }

    print_info("Demo Complete!\n");
}