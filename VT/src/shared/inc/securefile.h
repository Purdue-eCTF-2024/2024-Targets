/*
* @file securefile.h
* @brief This file contains the function declarations for the secure file
* @date 2024
* @author: CyberVT
* @note This file is part of the MITRE's 2024 Embedded System CTF (eCTF).
*/
/*********************************************************************************************************/
#include "stdio.h"
#include "string.h"
#include "stdbool.h"
#include "stdint.h"
#include "stdlib.h"

#include "RNG.h"
#include "uECC.h"
//#include "curve-specific.inc"

#define SUCCESS_RETURN 0
#define ERROR_RETURN -1
/*********************************************************************************************************/
/*
* @brief Sign a hash of a message
* @param privateKey: unsigned char *, private key to sign the message
* @param hash_message: unsigned char *, hash of the message
* @param curve: const struct uECC_Curve_t *, curve to use for signing
* @return uint8_t *, pointer to the signature of the message
*/
uint8_t * sign_key(char * privateKey, uint8_t * hash_message, const struct uECC_Curve_t * curve);
/*
* @brief Verify the signature of a message
* @param public_x: unsigned char *, x coordinate of the public key
* @param public_y: unsigned char *, y coordinate of the public key
* @param rec_hash: unsigned char *, hash of the message
* @param rec_signature: unsigned char *, signature to verify
* @param curve: const struct uECC_Curve_t *, curve to use for verification    
* @return int: 0 if signature is valid, -1 if signature is invalid
*/
int verify_key(char * public_x, char * public_y, uint8_t * rec_hash, uint8_t * rec_signature, const struct uECC_Curve_t * curve);
/*********************************************************************************************************/