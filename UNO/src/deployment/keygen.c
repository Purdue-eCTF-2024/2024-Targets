#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/aes.h>

int main() {
    WC_RNG rng;
	WC_RNG subrng;
    byte key[AES_256_KEY_SIZE]; // Change AES_256_KEY_SIZE to the desired key size
    byte key_key[AES_256_KEY_SIZE]; // Change AES_256_KEY_SIZE to the desired key size
	byte subKey[32]; // Magic number for Jake
	byte IV[16]; // IV for FUN

    // Initialize the random number generator
    if (wc_InitRng(&rng) != 0) {
        fprintf(stderr, "Failed to initialize RNG.\n");
        return 1;
    }

    // Generate a random AES key
    if (wc_RNG_GenerateBlock(&rng, key, sizeof(key)) != 0) {
        fprintf(stderr, "Failed to generate AES key.\n");
        wc_FreeRng(&rng);
        return 1;
    }

    if (wc_RNG_GenerateBlock(&rng, key_key, sizeof(key_key)) != 0) {
        fprintf(stderr, "Failed to generate AES key.\n");
        wc_FreeRng(&rng);
        return 1;
    }
	//Cleanup the RNG
	wc_FreeRng(&rng);
	
	// Initialize a new random number generator for Fun
    if (wc_InitRng(&subrng) != 0) {
        fprintf(stderr, "Failed to initialize RNG.\n");
        return 1;
    }
	
	// Generate another random AES key for Fun
    if (wc_RNG_GenerateBlock(&subrng, subKey, sizeof(subKey)) != 0) {
        fprintf(stderr, "Failed to generate AES key.\n");
        wc_FreeRng(&subrng);
        return 1;
    }
	
	// Generate another random IV key for Fun
    if (wc_RNG_GenerateBlock(&subrng, IV, sizeof(IV)) != 0) {
        fprintf(stderr, "Failed to generate AES key.\n");
        wc_FreeRng(&subrng);
        return 1;
    }

    // Clean up the RNG
    wc_FreeRng(&subrng);
	// moving to using fopen instead of stdout for more clarity.
	FILE *globalFile = NULL;
	globalFile = fopen("global_secrets.h", "w+");
	if (globalFile == NULL)
	{
		perror("Error: Unable to open globalFile");
	}

    // Print the AES key in the specified format
    fprintf(globalFile, "#define SECRET\n");
    fprintf(globalFile, "const unsigned char aes_key[] = {\n");
    for (int i = 0; i < sizeof(key); i++) {
        fprintf(globalFile, "    0x%02x", key[i]);
        if (i < sizeof(key) - 1) {
            fprintf(globalFile, ",");
        }
        if ((i + 1) % 4 == 0) {
            fprintf(globalFile, "\n");
        }
    }
    fprintf(globalFile, "};\n");
	
	fclose(globalFile);
	
    FILE *keyFile = NULL;
    keyFile = fopen("key_secrets.h", "w+");
    if (keyFile == NULL)
    {
        perror("Error: Unable to open keyFile");
    }

    fprintf(keyFile, "#define SECRET\n");
    fprintf(keyFile, "const unsigned char key_key[] = {\n");
    for (int i = 0; i < sizeof(key_key); i++) {
        fprintf(keyFile, "    0x%02x", key_key[i]);
        if (i < sizeof(key_key) - 1) {
            fprintf(keyFile, ",");
        }
        if ((i + 1) % 4 == 0) {
            fprintf(keyFile, "\n");
        }
    }
    fprintf(keyFile, "};\n");
    fclose(keyFile);
    
	globalFile = NULL;
	globalFile = fopen("semiFun_secrets.h", "w+");
	if (globalFile == NULL)
	{
		perror("Error: Unable to open globalFile");
	}
	
	
	 // Print the IV key in the specified format
    fprintf(globalFile, "#define FUNNY\n");
    fprintf(globalFile, "const unsigned char IV[] = {\n");
    for (int i = 0; i < sizeof(IV); i++) {
        fprintf(globalFile, "    0x%02x", IV[i]);
        if (i < sizeof(IV) - 1) {
            fprintf(globalFile, ",");
        }
        if ((i + 1) % 4 == 0) {
            fprintf(globalFile, "\n");
        }
    }
    fprintf(globalFile, "};\n");
	
	fclose(globalFile);
	
	// we are going to drop the fun secrets into a different file to make sure they arent accidentally included anywhere they shouldnt be.
	FILE *funFile = NULL;
	funFile = fopen("fun_secrets.h", "w+");
	if (funFile == NULL)
	{
		perror("Error: Unable to open funFile");
	}
	
	
	 // Print the AES key in the specified format
    fprintf(funFile, "#define FUNNY\n");
    fprintf(funFile, "const unsigned char subKey[] = {\n");
    for (int i = 0; i < sizeof(subKey); i++) {
        fprintf(funFile, "    0x%02x", subKey[i]);
        if (i < sizeof(subKey) - 1) {
            fprintf(funFile, ",");
        }
        if ((i + 1) % 4 == 0) {
            fprintf(funFile, "\n");
        }
    }
    fprintf(funFile, "};\n");

	fclose(funFile);
    return 0;
}
