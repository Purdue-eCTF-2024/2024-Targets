#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/aes.h>
#include "../../deployment/fun_secrets.h"
#include "../../deployment/semiFun_secrets.h"
#include "../../deployment/global_secrets.h"

int main() {

	
	/*
	*	Start Jake's terrible Code
	*/
	
	int ret;
	int subKeySize = 32;
	Aes enc;
	
	
	FILE *inFile;
	//FILE *outFile;
	
	// FIXME TODO cleanup code in ap to make sure everything is instatiated.
	inFile = NULL;
	//outFile = NULL;
	
	inFile = fopen("../inc/ectf_params.h", "r");
	if (inFile == NULL)
	{
		perror("Error: Unable to open inFile");
	}
	
	fseek(inFile, 0, SEEK_END);
    int inputLength = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
	int length = inputLength;
	
	
	ret = wc_AesInit(&enc, NULL, INVALID_DEVID);
    if (ret != 0) 
	{
        fprintf(stderr, "AesInit returned: %d\n", ret);
        return -1001;
    }

	ret = wc_AesSetKey(&enc, subKey, subKeySize,  IV, AES_ENCRYPTION);
	if (ret != 0) 
	{
        fprintf(stderr, "Failed to generate ACTUAL JAKE AES key. Error: %d\n", ret);
		return -2;
	}	

	byte* input;
	byte* output;
	
	input = malloc(length);

	
	ret = fread(input, 1, inputLength, inFile);
    if (ret == 0) 
	{
        fprintf(stderr, "True Input file does not exist.\n");
        return -1010;
    }
	
	/*
		Start token stuff here
	*/

	/*
	// I AM ON CRACK LETS OPERATE ON RAW BYTE STREAMS INSTEAD!
	*/
	
	// Something TODO-FIXME check where all null bytes are in file. 
	
	
	unsigned char locConst[15] = "ATTESTATION_LOC";
	
	int locIndex = 0;
	
	for (int i = 0; i < length; i++)
	{
		byte currPos = input[i];
		
		//fprintf(stdout, "%c", currPos);
		
		if (currPos == 'A')
		{
			int j;
			for(j = 1; j < 15; j++)
			{
				byte nextPos = input[i + j];
				if (nextPos != (byte) locConst[j])
				{
					j = 400;
				}
			}
			if (j != 400 && j != 401)
			{
				locIndex = i + 16;
			}
		}
	}
	
	if (locIndex == 0)
	{
		fprintf(stderr, "Error: Unable to determine location of attestation_loc data\n");
	}
	
	
	
	//Adjusting to include quotes so they can be used for indexing and to keep string.
	
	
	//fprintf(stderr, "locIndex = %c\n", input[locIndex]);
	int locIndexEnd;
	for (locIndexEnd = locIndex + 1; input[locIndexEnd] != '"'; locIndexEnd++);
	//fprintf(stderr, "locIndexEnd = %c\n", input[locIndexEnd]);
	
	// -1 disincludes the quote on the right
	int locLength = (locIndexEnd - locIndex) - 1;
	
	locIndex++;
	locIndexEnd--;
	
	byte* loc;
	loc = malloc(locLength);
	//fprintf(stderr, "%d \n", locIndexEnd);
	
	for (int i = 0; i < locLength; i++)
	{
		loc[i] = input[i+locIndex];
	}
	
	
	byte* tokenInput;
	int padCounter;
	int paddedLength = locLength;
	
	while (paddedLength % 16 != 0) 
	{
		paddedLength++;
		padCounter++;
	}
	
	output = malloc(paddedLength);

	tokenInput = malloc(paddedLength);
	for (int i =0; i < locLength; i++)
	{
		tokenInput[i] = loc[i];
	}
	for (int i = locLength; i < paddedLength; i++) 
	{ 
		// Pads with known non-used value
		tokenInput[i] = '!';
	}
	/*
	fprintf(stderr, "tokenInput = ");
	for (int i = 0; i < paddedLength; i++)
	{
		fprintf(stderr, "%c", tokenInput[i]);
	}
	fprintf(stderr, "\n");
	*/
	ret = wc_AesCbcEncrypt(&enc, output, tokenInput, paddedLength);
	if (ret != 0) 
	{
		fprintf(stderr, "Error: Unable to encrypt file contents retCode= %d\n", ret);
		return -1001;
	}

	
	

	// base64 was the goal because large
	
	byte* basedOutput;
	basedOutput = malloc(paddedLength * sizeof(int));

	int basedLength = paddedLength * sizeof(int); 
	ret = Base64_Encode_NoNl(output, paddedLength, basedOutput, &basedLength);
	if (ret !=0)
	{
		fprintf(stderr, "Error: Could Not basedEncode %d\n", ret);
	}
	
	// TODO FIXME remove everything to do with the outfile 
	//fwrite(basedOutput, 1, basedLength, outFile);


	// outputting into buffer so it can be thrown back into the params folder.
	// Right now we have input buffer full of ectf_params and its open as inFile
	
	
	byte* replaceOutput;
	replaceOutput = malloc(length+basedLength - locLength);
	
	for(int i = 0; i < locIndex; i++)
	{
		replaceOutput[i] = input[i];
	}
	for (int i = 0; i < basedLength; i++)
	{
		replaceOutput[locIndex+i] = basedOutput[i];
	}
	for (int i = 0; i + (locIndex+1) < length&& i < length - locIndexEnd; i++)
	{
		replaceOutput[locIndex+basedLength+i] = input[locIndexEnd + 1 + i];
	}
	
	
	
	fclose(inFile);
	
	
	
	/*
	FILE *outFile2;
	
	outFile2 = fopen("test2.txt", "r+");
	if (outFile2 == NULL)
	{
		perror("Error: Unable to open the OTHER outFile");
	}
	*/
	inFile = fopen("../inc/ectf_params.h", "w");
	if (inFile == NULL)
	{
		perror("Error: Unable to open inFile");
	}

	
	fwrite(replaceOutput, 1, length + basedLength - locLength, inFile);
	//fclose(outFile2);
	
	
	
	
	// End the section of output into params
	

	
    free(input);
    free(output);
	free(loc);
	free(tokenInput);
	free(basedOutput);
	free(replaceOutput);
    fclose(inFile);
    //fclose(outFile);
	
	
	
	
	
	
	/*
	/ Everything above this line just does the 1x location parameter. Below this is me doing the code to replicate with the next 2 params.
	/ Its going to look messy... Oops. This should've all been done as functions but & and * are rough and its too late now to go back through 
	/ and properly manage all my variables.
	/ IT ISSS WHAT IT ISSS
	*/ 
	
	
	
	inFile = NULL;
	//outFile = NULL;
	
	inFile = fopen("../inc/ectf_params.h", "r");
	if (inFile == NULL)
	{
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
    inputLength = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
	length = inputLength;
	
	ret = wc_AesSetKey(&enc, subKey, subKeySize,  IV, AES_ENCRYPTION);
	if (ret != 0) 
	{
        fprintf(stderr, "Failed to generate ACTUAL JAKE AES key. Error: %d\n", ret);
		return -2;
	}	

	input = malloc(length);

	
	ret = fread(input, 1, inputLength, inFile);
    if (ret == 0) 
	{
        fprintf(stderr, "True Input file does not exist.\n");
        return -1010;
    }
	
	/*
		Start token stuff here
	*/

	/*
	// I AM ON CRACK LETS OPERATE ON RAW BYTE STREAMS INSTEAD!
	*/
	
	// Something TODO-FIXME check where all null bytes are in file. 
	
	
	unsigned char dateConst[16] = "ATTESTATION_DATE";
	
	locIndex = 0;
	
	for (int i = 0; i < length; i++)
	{
		byte currPos = input[i];
		
		//fprintf(stdout, "%c", currPos);
		
		if (currPos == 'A')
		{
			int j;
			for(j = 1; j < 16; j++)
			{
				byte nextPos = input[i + j];
				if (nextPos != (byte) dateConst[j])
				{
					j = 400;
				}
			}
			if (j != 400 && j != 401)
			{
				locIndex = i + 17;
			}
		}
	}
	
	if (locIndex == 0)
	{
		fprintf(stderr, "Error: Unable to determine location of attestation_date data\n");
	}
	
	
	
	//Adjusting to include quotes so they can be used for indexing and to keep string.
	
	
	//fprintf(stderr, "locIndex = %c\n", input[locIndex]);

	for (locIndexEnd = locIndex + 1; input[locIndexEnd] != '"'; locIndexEnd++);
	//(stderr, "locIndexEnd = %c\n", input[locIndexEnd]);
	
	// -1 disincludes the quote on the right
	locLength = (locIndexEnd - locIndex) - 1;
	
	locIndex++;
	locIndexEnd--;
	
	loc = malloc(locLength);
	
	for (int i = 0; i < locLength; i++)
	{
		loc[i] = input[i+locIndex];
	}
	
	
	padCounter = 0;
	paddedLength = locLength;
	
	while (paddedLength % 16 != 0) 
	{
		paddedLength++;
		padCounter++;
	}
	
	output = malloc(paddedLength);

	tokenInput = malloc(paddedLength);
	for (int i =0; i < locLength; i++)
	{
		tokenInput[i] = loc[i];
	}
	for (int i = locLength; i < paddedLength; i++) 
	{ 
		// Pads with known non-used value
		tokenInput[i] = '!';
	}
	/*
	fprintf(stderr, "tokenInput = ");
	for (int i = 0; i < paddedLength; i++)
	{
		fprintf(stderr, "%c", tokenInput[i]);
	}
	fprintf(stderr, "\n");
	*/
	ret = wc_AesCbcEncrypt(&enc, output, tokenInput, paddedLength);
	if (ret != 0) 
	{
		fprintf(stderr, "Error: Unable to encrypt file contents retCode= %d\n", ret);
		return -1001;
	}

	
	

	// base64 was the goal because large
	
	basedOutput = malloc(paddedLength * sizeof(int));

	basedLength = paddedLength * sizeof(int); 
	ret = Base64_Encode_NoNl(output, paddedLength, basedOutput, &basedLength);
	if (ret !=0)
	{
		fprintf(stderr, "Error: Could Not basedEncode %d\n", ret);
	}
	
	// TODO FIXME remove everything to do with the outfile 
	//fwrite(basedOutput, 1, basedLength, outFile);
	
	
	// outputting into buffer so it can be thrown back into the params folder.
	// Right now we have input buffer full of ectf_params and its open as inFile
	
	

	replaceOutput = malloc(length+basedLength - locLength);
	
	for(int i = 0; i < locIndex; i++)
	{
		replaceOutput[i] = input[i];
	}
	for (int i = 0; i < basedLength; i++)
	{
		replaceOutput[locIndex+i] = basedOutput[i];
	}
	for (int i = 0; i + (locIndex+1) < length&& i < length - locIndexEnd; i++)
	{
		replaceOutput[locIndex+basedLength+i] = input[locIndexEnd + 1 + i];
	}
	
	
	
	fclose(inFile);
	

	inFile = fopen("../inc/ectf_params.h", "w");
	if (inFile == NULL)
	{
		perror("Error: Unable to open inFile");
	}

	
	fwrite(replaceOutput, 1, length + basedLength - locLength, inFile);
	
	// End the section of output into params
	
	
	
	fclose(inFile);
	//fclose(outFile);
	free(input);
	free(output);
	free(loc);
	free(basedOutput);
	free(tokenInput);
	free(replaceOutput);
	
	
	
	
	/*
	/ And lets repeat a third time to calculate the third value
	/
	/
	/
	/ IT ISSS WHAT IT ISSS
	*/ 
	
	
	
	inFile = NULL;
	
	inFile = fopen("../inc/ectf_params.h", "r");
	if (inFile == NULL)
	{
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
    inputLength = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);
	length = inputLength;
	
	ret = wc_AesSetKey(&enc, subKey, subKeySize,  IV, AES_ENCRYPTION);
	if (ret != 0) 
	{
        fprintf(stderr, "Failed to generate ACTUAL JAKE AES key. Error: %d\n", ret);
		return -2;
	}	

	input = malloc(length);

	
	ret = fread(input, 1, inputLength, inFile);
    if (ret == 0) 
	{
        fprintf(stderr, "True Input file does not exist.\n");
        return -1010;
    }
	
	/*
		Start token stuff here
	*/

	/*
	// I AM ON CRACK LETS OPERATE ON RAW BYTE STREAMS INSTEAD!
	*/
	
	// Something TODO-FIXME check where all null bytes are in file. 
	
	
	unsigned char custConst[20] = "ATTESTATION_CUSTOMER";
	
	locIndex = 0;
	
	for (int i = 0; i < length; i++)
	{
		byte currPos = input[i];
		
		//fprintf(stdout, "%c", currPos);
		
		if (currPos == 'A')
		{
			int j;
			for(j = 1; j < 20; j++)
			{
				byte nextPos = input[i + j];
				if (nextPos != (byte) custConst[j])
				{
					j = 400;
				}
			}
			if (j != 400 && j != 401)
			{
				locIndex = i + 21;
			}
		}
	}
	
	if (locIndex == 0)
	{
		fprintf(stderr, "Error: Unable to determine location of attestation_date data\n");
	}
	
	
	
	//Adjusting to include quotes so they can be used for indexing and to keep string.
	
	
	//fprintf(stderr, "locIndex = %c\n", input[locIndex]);

	for (locIndexEnd = locIndex + 1; input[locIndexEnd] != '"'; locIndexEnd++);
	//fprintf(stderr, "locIndexEnd = %c\n", input[locIndexEnd]);
	
	// -1 disincludes the quote on the right
	locLength = (locIndexEnd - locIndex) - 1;
	
	locIndex++;
	locIndexEnd--;
	
	loc = malloc(locLength);
	
	for (int i = 0; i < locLength; i++)
	{
		loc[i] = input[i+locIndex];
	}
	
	
	padCounter = 0;
	paddedLength = locLength;
	
	while (paddedLength % 16 != 0) 
	{
		paddedLength++;
		padCounter++;
	}
	
	output = malloc(paddedLength);

	tokenInput = malloc(paddedLength);
	for (int i =0; i < locLength; i++)
	{
		tokenInput[i] = loc[i];
	}
	for (int i = locLength; i < paddedLength; i++) 
	{ 
		// Pads with known non-used value
		tokenInput[i] = '!';
	}
	
	/*
	fprintf(stderr, "tokenInput = ");
	for (int i = 0; i < paddedLength; i++)
	{
		fprintf(stderr, "%c", tokenInput[i]);
	}
	fprintf(stderr, "\n");
	*/
	ret = wc_AesCbcEncrypt(&enc, output, tokenInput, paddedLength);
	if (ret != 0) 
	{
		fprintf(stderr, "Error: Unable to encrypt file contents retCode= %d\n", ret);
		return -1001;
	}

	
	

	// base64 was the goal because large
	
	basedOutput = malloc(paddedLength * sizeof(int));

	basedLength = paddedLength * sizeof(int); 
	ret = Base64_Encode_NoNl(output, paddedLength, basedOutput, &basedLength);
	if (ret !=0)
	{
		fprintf(stderr, "Error: Could Not basedEncode %d\n", ret);
	}
	
	// TODO FIXME remove everything to do with the outfile 
	//fwrite(basedOutput, 1, basedLength, outFile);
	
	
	// outputting into buffer so it can be thrown back into the params folder.
	// Right now we have input buffer full of ectf_params and its open as inFile
	
	

	replaceOutput = malloc(length+basedLength - locLength);
	
	for(int i = 0; i < locIndex; i++)
	{
		replaceOutput[i] = input[i];
	}
	for (int i = 0; i < basedLength; i++)
	{
		replaceOutput[locIndex+i] = basedOutput[i];
	}
	for (int i = 0; i + (locIndex+1) < length&& i < length - locIndexEnd; i++)
	{
		replaceOutput[locIndex+basedLength+i] = input[locIndexEnd + 1 + i];
	}
	
	
	
	fclose(inFile);
	

	inFile = fopen("../inc/ectf_params.h", "w");
	if (inFile == NULL)
	{
		perror("Error: Unable to open inFile");
	}

	
	fwrite(replaceOutput, 1, length + basedLength - locLength, inFile);
	
	// End the section of output into params
	
   
   
	fclose(inFile);
	//fclose(outFile);
	free(input);
	free(output);
	free(loc);
	free(basedOutput);
	free(tokenInput);
	free(replaceOutput);
   
	
    // Cleanup wolfSSL library
    wolfSSL_Cleanup();

    return 0;
}