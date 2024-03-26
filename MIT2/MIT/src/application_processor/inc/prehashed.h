#ifndef _PREHASHED_H_
#define _PREHASHED_H_

#ifdef __cplusplus

const uint8_t * getHashedPinPtrCpp(void);
const uint8_t * getHashedTokenPtrCpp(void);

#endif

#ifdef __cplusplus
extern "C" {
#endif

const uint8_t * getHashedPinPtr(void);
const uint8_t * getHashedTokenPtr(void);


#ifdef __cplusplus
}
#endif

#endif