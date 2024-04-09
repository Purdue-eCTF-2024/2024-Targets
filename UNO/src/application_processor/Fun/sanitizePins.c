#include "../../deployment/fun_secrets.h"
#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/random.h>

int main() {

    /*
     *	Start Jake's terrible Code
     */

    int ret;
    int subKeySize = 32;

    FILE *inFile;
    // FILE *outFile;

    // FIXME TODO cleanup code in ap to make sure everything is instatiated.
    inFile = NULL;
    // outFile = NULL;

    inFile = fopen("../inc/ectf_params.h", "r");
    if (inFile == NULL) {
        perror("Error: Unable to open inFile");
    }
    /*
    outFile = fopen("test.txt", "w+");
    if (outFile == NULL)
    {
            perror("Error: Unable to open outFile");
    }
    */
    fseek(inFile, 0, SEEK_END);
    int inputLength = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
    int length = inputLength;

    byte *input;
    byte *output;

    input = malloc(length);

    ret = fread(input, 1, inputLength, inFile);
    if (ret == 0) {
        fprintf(stderr, "True Input file does not exist.\n");
        return -1010;
    }

    /*
            Start token stuff here
    */

    /*
    // I AM ON CRACK LETS OPERATE ON RAW BYTE STREAMS INSTEAD!
    */

    unsigned char locConst[6] = "AP_PIN";

    int locIndex = 0;

    for (int i = 0; i < length; i++) {
        byte currPos = input[i];

        // fprintf(stdout, "%c", currPos);

        if (currPos == 'A') {
            int j;
            for (j = 1; j < 6; j++) {
                byte nextPos = input[i + j];
                if (nextPos != (byte)locConst[j]) {
                    j = 400;
                }
            }
            if (j != 400 && j != 401) {
                locIndex = i + 7;
                // size of cons + 1
            }
        }
    }

    if (locIndex == 0) {
        fprintf(
            stderr,
            "Error: Unable to determine location of attestation_loc data\n");
    }

    // Adjusting to include quotes so they can be used for indexing and to keep
    // string.

    // fprintf(stderr, "locIndex = %c\n", input[locIndex]);
    int locIndexEnd;
    for (locIndexEnd = locIndex + 1; input[locIndexEnd] != '"'; locIndexEnd++)
        ;
    // fprintf(stderr, "locIndexEnd = %c\n", input[locIndexEnd]);

    // -1 disincludes the quote on the right
    int locLength = (locIndexEnd - locIndex) - 1;

    locIndex++;
    locIndexEnd--;

    byte *loc;
    loc = malloc(locLength);
    // fprintf(stderr, "%d \n", locIndexEnd);

    for (int i = 0; i < locLength; i++) {
        loc[i] = input[i + locIndex];
    }

    // At this point loc is our byte stream of the AP_PIN value
    // Now we need to combine this with our IV in a reversible (only with
    // knowledge of pin) way.

    int lengthKey = 32;
    byte *newKey = malloc(lengthKey);

    // fprintf(stderr,"newKey = ");
    for (int i = 0; i < lengthKey; i++) {
        newKey[i] = subKey[i] ^ loc[i % 6];
        // fprintf(stderr, "%02X", newKey[i]);
    }
    // fprintf(stderr, "\n");

    // base64 was the goal because large

    byte *basedOutput = malloc(lengthKey * 4);

    word32 basedLength = lengthKey * sizeof(int);
    ret = Base64_Encode_NoNl(newKey, lengthKey, basedOutput, &basedLength);
    if (ret != 0) {
        fprintf(stderr, "Error: Could Not Base64 Encode: %d\n", ret);
    }

    // TODO FIXME remove everything to do with the outfile
    // fwrite(basedOutput, 1, basedOutput, outFile);

    // outputting into buffer so it can be thrown back into the params folder.
    // Right now we have input buffer full of ectf_params and its open as inFile

    byte *replaceOutput = malloc(length + basedLength - locLength);

    for (int i = 0; i < locIndex; i++) {
        replaceOutput[i] = input[i];
    }
    for (int i = 0; i < basedLength; i++) {
        replaceOutput[locIndex + i] = basedOutput[i];
    }
    for (int i = 0; i + (locIndex + 1) < length && i < length - locIndexEnd;
         i++) {
        replaceOutput[locIndex + basedLength + i] = input[locIndexEnd + 1 + i];
    }

    fclose(inFile);

    inFile = fopen("../inc/ectf_params.h", "w");
    if (inFile == NULL) {
        perror("Error: Unable to open inFile");
    }

    fwrite(replaceOutput, 1, length + basedLength - locLength, inFile);

    // End the section of output into params
    free(input);
    free(output);
    free(basedOutput);
    free(replaceOutput);
    // Cleanup wolfSSL library
    wolfSSL_Cleanup();
    fclose(inFile);
    free(loc);

    return 0;
}