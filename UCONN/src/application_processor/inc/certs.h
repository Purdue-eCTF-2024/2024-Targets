/**
 * @file "certs.h"
 * @author Kevin Marquis
 * @brief Device Secrets Header File
 * @date 2024
 */


#ifndef DEV_SECRETS
#define DEV_SECRETS

extern const unsigned char DEVICE_PUB_DER[];
extern const int DEVICE_PUB_DER_LEN;

extern const unsigned char DEVICE_SIG[];
extern const int DEVICE_SIG_LEN;


extern const unsigned char DEVICE_KEY[];
extern const int DEVICE_KEY_DER_LEN;


extern const unsigned char CA_PUB_DER[];
extern const int CA_PUB_DER_LEN;

#endif