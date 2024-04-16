/* fips.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */



#ifndef WOLF_CRYPT_FIPS_H
#define WOLF_CRYPT_FIPS_H


#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/fips_test.h>

#ifdef __cplusplus
    extern "C" {
#endif


/* mp_int */
/* provide opaque definition for math int type */
#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)
    struct sp_int;
    #define MP_INT_T struct sp_int
#elif defined(USE_FAST_MATH)
    struct fp_int;
    #define MP_INT_T struct fp_int
#else
    struct mp_int;
    #define MP_INT_T struct mp_int
#endif

WOLFSSL_API const char* wolfCrypt_GetVersion_fips(void);
WOLFSSL_API int wolfCrypt_IntegrityTest_fips(void);

#ifdef WOLFSSL_LINUXKM
typedef atomic_t fipsCastStateId_t;
#define fipsCastStateId_read(x) atomic_read(&(x))
#define fipsCastStateId_set(x, y) atomic_set(&(x), y)
#else
typedef enum FipsCastStateId fipsCastStateId_t;
#define fipsCastStateId_read(x) (x)
#define fipsCastStateId_set(x,y) ((x) = (y))
#endif
WOLFSSL_LOCAL extern fipsCastStateId_t fipsCastStatus[FIPS_CAST_COUNT];
#define fipsCastStatus_get(x) fipsCastStateId_read(fipsCastStatus[x])
#define fipsCastStatus_put(x, y) fipsCastStateId_set(fipsCastStatus[x], y)


enum wc_KeyType {
    WC_KEYTYPE_ALL = 0
};
WOLFSSL_API int wolfCrypt_SetPrivateKeyReadEnable_fips(int enable,
                                                       enum wc_KeyType keyType);
WOLFSSL_API int wolfCrypt_GetPrivateKeyReadEnable_fips(enum wc_KeyType keyType);


/* Hash_DRBG API */
#if defined(HAVE_HASHDRBG) || defined(CUSTOM_RAND_GENERATE_BLOCK)

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_RNG_TYPE_DEFINED
        typedef struct OS_Seed OS_Seed;
        typedef struct WC_RNG WC_RNG;
        #ifdef WC_RNG_SEED_CB
        typedef int (*wc_RngSeed_Cb)(OS_Seed* os, byte* seed, word32 sz);
        #endif
        #define WC_RNG_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitRng_fips(WC_RNG* rng);
    WOLFSSL_API int wc_InitRngNonce_fips(WC_RNG* rng, byte* nonce,
                                         word32 nonceSz);
    WOLFSSL_API int wc_FreeRng_fips(WC_RNG* rng);
    #ifdef WC_RNG_SEED_CB
    WOLFSSL_API int wc_SetSeed_Cb_fips(wc_RngSeed_Cb cb);
    #endif
    WOLFSSL_API int wc_RNG_GenerateBlock_fips(WC_RNG* rng, byte* buf,
                                              word32 bufSz);
    WOLFSSL_API int wc_RNG_HealthTest_fips(
        int reseed, const byte* entropyA, word32 entropyASz,
        const byte* entropyB, word32 entropyBSz, byte* output, word32 outputSz);

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitRng                  wc_InitRng_fips
    #define wc_InitRngNonce             wc_InitRngNonce_fips
    #define wc_FreeRng                  wc_FreeRng_fips
    #define wc_SetSeed_Cb               wc_SetSeed_Cb_fips
    #define wc_RNG_GenerateBlock        wc_RNG_GenerateBlock_fips
    #define wc_RNG_HealthTest           wc_RNG_HealthTest_fips

    #define InitRng_fips                wc_InitRng_fips
    #define InitRngNonce_fips           wc_InitRngNonce_fips
    #define FreeRng_fips                wc_FreeRng_fips
    #define SetSeed_Cb_fips             wc_SetSeed_Cb_fips
    #define RNG_GenerateBlock_fips      wc_RNG_GenerateBlock_fips
    #define RNG_HealthTest_fips         wc_RNG_HealthTest_fips
#endif /* FIPS_NO_WRAPPERS */

#endif /* HAVE_HASHDRBG */


/* AES API */
#ifndef NO_AES

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_AES_TYPE_DEFINED
        typedef struct Aes Aes;
        #define WC_AES_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_AesSetKey_fips(Aes* aes, const byte* userKey,
                                      word32 keylen, const byte* iv, int dir);
    WOLFSSL_API int wc_AesSetIV_fips(Aes* aes, const byte* iv);
    WOLFSSL_API int wc_AesEcbEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesEcbDecrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesCbcEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesCbcDecrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesCtrEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesCtrSetKey_fips(Aes* aes, const byte* key, word32 len,
                                         const byte* iv, int dir);
    WOLFSSL_API int wc_AesOfbEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesOfbDecrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz);
    WOLFSSL_API int wc_AesGcmSetKey_fips(Aes* aes, const byte* key, word32 len);
    WOLFSSL_API int wc_AesGcmSetExtIV_fips(Aes* aes, const byte* iv,
                                           word32 ivSz);
    WOLFSSL_API int wc_AesGcmSetIV_fips(Aes* aes, word32 ivSz,
                                        const byte* ivFixed, word32 ivFixedSz,
                                        WC_RNG* rng);
    WOLFSSL_API int wc_AesGcmEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz,
                                          byte* ivOut, word32 ivOutSz,
                                          byte* authTag, word32 authTagSz,
                                          const byte* authIn, word32 authInSz);
    WOLFSSL_API int wc_AesGcmDecrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz,
                                          const byte* iv, word32 ivSz,
                                          const byte* authTag, word32 authTagSz,
                                          const byte* authIn, word32 authInSz);
    WOLFSSL_API int wc_Gmac_fips(const byte* key, word32 keySz, byte* iv,
                                 word32 ivSz,
                                 const byte* authIn, word32 authInSz,
                                 byte* authTag, word32 authTagSz, WC_RNG* rng);
    WOLFSSL_API int wc_GmacVerify_fips(const byte* key, word32 keySz,
                                       const byte* iv, word32 ivSz,
                                       const byte* authIn, word32 authInSz,
                                       const byte* authTag, word32 authTagSz);
    WOLFSSL_API int wc_AesCcmSetKey_fips(Aes* aes, const byte* key, word32 len);
    WOLFSSL_API int wc_AesCcmSetNonce_fips(Aes* aes, const byte* nonce,
                                           word32 nonceSz);
    WOLFSSL_API int wc_AesCcmEncrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz,
                                          byte* ivOut, word32 ivOutSz,
                                          byte* authTag, word32 authTagSz,
                                          const byte* authIn, word32 authInSz);
    WOLFSSL_API int wc_AesCcmDecrypt_fips(Aes* aes, byte* out, const byte* in,
                                          word32 sz,
                                          const byte* iv, word32 ivSz,
                                          const byte* authTag, word32 authTagSz,
                                          const byte* authIn, word32 authInSz);

#else /* NO_FIPS_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_AesSetKey               wc_AesSetKey_fips
    #define wc_AesSetIV                wc_AesSetIV_fips
    #define wc_AesEcbEncrypt           wc_AesEcbEncrypt_fips
    #define wc_AesEcbDecrypt           wc_AesEcbDecrypt_fips
    #define wc_AesCbcEncrypt           wc_AesCbcEncrypt_fips
    #define wc_AesCbcDecrypt           wc_AesCbcDecrypt_fips
    #define wc_AesCtrEncrypt           wc_AesCtrEncrypt_fips
    #define wc_AesCtrSetKey            wc_AesCtrSetKey_fips
    #define wc_AesOfbEncrypt           wc_AesOfbEncrypt_fips
    #define wc_AesOfbDecrypt           wc_AesOfbDecrypt_fips
    #define wc_AesGcmSetKey            wc_AesGcmSetKey_fips
    #define wc_AesGcmSetExtIV          wc_AesGcmSetExtIV_fips
    #define wc_AesGcmSetIV             wc_AesGcmSetIV_fips
    #define wc_AesGcmEncrypt_ex        wc_AesGcmEncrypt_fips
    #define wc_AesGcmDecrypt           wc_AesGcmDecrypt_fips
    #define wc_AesCcmSetKey            wc_AesCcmSetKey_fips
    #define wc_AesCcmSetNonce          wc_AesCcmSetNonce_fips
    #define wc_AesCcmEncrypt_ex        wc_AesCcmEncrypt_fips
    #define wc_AesCcmDecrypt           wc_AesCcmDecrypt_fips
    #define wc_Gmac                    wc_Gmac_fips
    #define wc_GmacVerify              wc_GmacVerify_fips

    #define AesSetKey_fips             wc_AesSetKey_fips
    #define AesSetIV_fips              wc_AesSetIV_fips
    #define AesEcbEncrypt_fips         wc_AesEcbEncrypt_fips
    #define AesEcbDecrypt_fips         wc_AesEcbDecrypt_fips
    #define AesCbcEncrypt_fips         wc_AesCbcEncrypt_fips
    #define AesCbcDecrypt_fips         wc_AesCbcDecrypt_fips
    #define AesCtrEncrypt_fips         wc_AesCtrEncrypt_fips
    #define AesCtrSetKey_fips          wc_AesCtrSetKey_fips
    #define AesOfbEncrypt_fips         wc_AesOfbEncrypt_fips
    #define AesOfbDecrypt_fips         wc_AesOfbDecrypt_fips
    #define AesGcmSetKey_fips          wc_AesGcmSetKey_fips
    #define AesGcmSetExtIV_fips        wc_AesGcmSetExtIV_fips
    #define AesGcmSetIV_fips           wc_AesGcmSetIV_fips
    #define AesGcmEncrypt_fips         wc_AesGcmEncrypt_fips
    #define AesGcmDecrypt_fips         wc_AesGcmDecrypt_fips
    #define AesCcmSetKey_fips          wc_AesCcmSetKey_fips
    #define AesCcmSetNonce_fips        wc_AesCcmSetNonce_fips
    #define AesCcmEncrypt_ex_fips      wc_AesCcmEncrypt_fips
    #define AesCcmDecrypt_fips         wc_AesCcmDecrypt_fips
#endif /* NO_FIPS_WRAPPERS */

#endif /* NO_AES */


/* RSA API */
#ifndef NO_RSA

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_RSAKEY_TYPE_DEFINED
        typedef struct RsaKey RsaKey;
        #define WC_RSAKEY_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitRsaKey_fips(RsaKey* key, void* p);
    WOLFSSL_API int wc_InitRsaKeyEx_fips(RsaKey* key, void* p, int devId);
    WOLFSSL_API int wc_FreeRsaKey_fips(RsaKey* key);
    WOLFSSL_API int wc_CheckRsaKey_fips(RsaKey* key);
    WOLFSSL_API int wc_RsaPublicEncrypt_fips(const byte* in, word32 inLen,
                                             byte* out, word32 outLen,
                                             RsaKey* key, WC_RNG* rng);
    WOLFSSL_API int wc_RsaPublicEncryptEx_fips(const byte* in, word32 inLen,
                                               byte* out, word32 outLen,
                                               RsaKey* key, WC_RNG* rng,
                                               int type, enum wc_HashType hash,
                            int mgf, byte* label, word32 labelSz);
    WOLFSSL_API int wc_RsaPrivateDecryptInline_fips(byte* in, word32 inLen,
                                                    byte** out, RsaKey* key);
    WOLFSSL_API int wc_RsaPrivateDecryptInlineEx_fips(
        byte* in, word32 inLen, byte** out, RsaKey* key, int type,
        enum wc_HashType hash, int mgf, byte* label, word32 labelSz);
    WOLFSSL_API int wc_RsaPrivateDecrypt_fips(
        const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key);
    WOLFSSL_API int wc_RsaPrivateDecryptEx_fips(
        const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key,
        int type, enum wc_HashType hash, int mgf, byte* label, word32 labelSz);
    WOLFSSL_API int wc_RsaSSL_Sign_fips(
        const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key,
        WC_RNG* rng);
    WOLFSSL_API int wc_RsaSSL_VerifyInline_fips(
        byte* in, word32 inLen, byte** out, RsaKey* key);
    WOLFSSL_API int wc_RsaSSL_Verify_fips(
        const byte* in, word32 inLen, byte* out, word32 outLen, RsaKey* key);
    WOLFSSL_API int wc_RsaPSS_Sign_fips(
        const byte* in, word32 inLen, byte* out, word32 outLen,
        enum wc_HashType hash, int mgf, RsaKey* key, WC_RNG* rng);
    WOLFSSL_API int wc_RsaPSS_SignEx_fips(
        const byte* in, word32 inLen, byte* out, word32 outLen,
        enum wc_HashType hash, int mgf, int saltLen, RsaKey* key, WC_RNG* rng);
    WOLFSSL_API int wc_RsaPSS_VerifyInline_fips(
        byte* in, word32 inLen, byte** out, enum wc_HashType hash, int mgf,
        RsaKey* key);
    WOLFSSL_API int wc_RsaPSS_VerifyInlineEx_fips(
        byte* in, word32 inLen, byte** out, enum wc_HashType hash, int mgf,
        int saltLen, RsaKey* key);
    WOLFSSL_API int wc_RsaPSS_Verify_fips(
        byte* in, word32 inLen, byte* out, word32 outLen, enum wc_HashType hash,
        int mgf, RsaKey* key);
    WOLFSSL_API int wc_RsaPSS_VerifyEx_fips(
        byte* in, word32 inLen, byte* out, word32 outLen, enum wc_HashType hash,
        int mgf, int saltLen, RsaKey* key);
    WOLFSSL_API int wc_RsaPSS_CheckPadding_fips(
        const byte* in, word32 inSz, byte* sig, word32 sigSz,
        enum wc_HashType hashType);
    WOLFSSL_API int wc_RsaPSS_CheckPaddingEx_fips(
        const byte* in, word32 inSz, byte* sig, word32 sigSz,
        enum wc_HashType hashType, int saltLen, int bits);
    WOLFSSL_API int wc_RsaEncryptSize_fips(RsaKey* key);
    WOLFSSL_API int wc_RsaExportKey_fips(
        RsaKey* key, byte* e, word32* eSz, byte* n, word32* nSz, byte* d,
        word32* dSz, byte* p, word32* pSz, byte* q, word32* qSz);
#if 0
    WOLFSSL_API int wc_CheckProbablePrime_fips(
        const byte* p, word32 pSz, const byte* q, word32 qSz, const byte* e,
        word32 eSz, int nlen, int* isPrime);
#endif
    WOLFSSL_API int wc_MakeRsaKey_fips(RsaKey* key, int size, long e,
                                       WC_RNG* rng);

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitRsaKey              wc_InitRsaKey_fips
    #define wc_InitRsaKey_ex           wc_InitRsaKeyEx_fips
    #define wc_FreeRsaKey              wc_FreeRsaKey_fips
    #define wc_CheckRsaKey             wc_CheckRsaKey_fips
    #define wc_RsaPublicEncrypt        wc_RsaPublicEncrypt_fips
    #define wc_RsaPublicEncrypt_ex     wc_RsaPublicEncryptEx_fips
    #define wc_RsaPrivateDecryptInline wc_RsaPrivateDecryptInline_fips
    #define wc_RsaPrivateDecryptInline_ex wc_RsaPrivateDecryptInlineEx_fips
    #define wc_RsaPrivateDecrypt       wc_RsaPrivateDecrypt_fips
    #define wc_RsaPrivateDecrypt_ex    wc_RsaPrivateDecryptEx_fips
    #define wc_RsaSSL_Sign             wc_RsaSSL_Sign_fips
    #define wc_RsaSSL_VerifyInline     wc_RsaSSL_VerifyInline_fips
    #define wc_RsaSSL_Verify           wc_RsaSSL_Verify_fips
    #define wc_RsaPSS_Sign             wc_RsaPSS_Sign_fips
    #define wc_RsaPSS_Sign_ex          wc_RsaPSS_SignEx_fips
    #define wc_RsaPSS_VerifyInline     wc_RsaPSS_VerifyInline_fips
    #define wc_RsaPSS_VerifyInline_ex  wc_RsaPSS_VerifyInlineEx_fips
    #define wc_RsaPSS_Verify           wc_RsaPSS_Verify_fips
    #define wc_RsaPSS_Verify_ex        wc_RsaPSS_VerifyEx_fips
    #define wc_RsaPSS_CheckPadding     wc_RsaPSS_CheckPadding_fips
    #define wc_RsaPSS_CheckPadding_ex  wc_RsaPSS_CheckPaddingEx_fips
    #define wc_RsaEncryptSize          wc_RsaEncryptSize_fips
    #define wc_RsaExportKey            wc_RsaExportKey_fips
    #define wc_MakeRsaKey              wc_MakeRsaKey_fips

    #define InitRsaKey_fips            wc_InitRsaKey_fips
    #define InitRsaKey_ex_fips         wc_InitRsaKeyEx_fips
    #define FreeRsaKey_fips            wc_FreeRsaKey_fips
    #define CheckRsaKey_fips           wc_CheckRsaKey_fips
    #define RsaPublicEncrypt_fips      wc_RsaPublicEncrypt_fips
    #define RsaPublicEncrypt_ex_fips   wc_RsaPublicEncryptEx_fips
    #define RsaPrivateDecryptInline_fips wc_RsaPrivateDecryptInline_fips
    #define RsaPrivateDecryptInline_ex_fips wc_RsaPrivateDecryptInlineEx_fips
    #define RsaPrivateDecrypt_fips     wc_RsaPrivateDecrypt_fips
    #define RsaPrivateDecrypt_ex_fips  wc_RsaPrivateDecryptEx_fips
    #define RsaSSL_Sign_fips           wc_RsaSSL_Sign_fips
    #define RsaSSL_VerifyInline_fips   wc_RsaSSL_VerifyInline_fips
    #define RsaSSL_Verify_fips         wc_RsaSSL_Verify_fips
    #define RsaPSS_Sign_fips           wc_RsaPSS_Sign_fips
    #define RsaPSS_Sign_ex_fips        wc_RsaPSS_SignEx_fips
    #define RsaPSS_VerifyInline_fips   wc_RsaPSS_VerifyInline_fips
    #define RsaPSS_VerifyInline_ex_fips wc_RsaPSS_VerifyInlineEx_fips
    #define RsaPSS_Verify_fips         wc_RsaPSS_Verify_fips
    #define RsaPSS_Verify_ex_fips      wc_RsaPSS_VerifyEx_fips
    #define RsaPSS_CheckPadding_fips   wc_RsaPSS_CheckPadding_fips
    #define RsaPSS_CheckPadding_ex_fips wc_RsaPSS_CheckPaddingEx_fips
    #define RsaEncryptSize_fips        wc_RsaEncryptSize_fips
    #define RsaExportKey_fips          wc_RsaExportKey_fips
    #define MakeRsaKey_fips            wc_MakeRsaKey_fips
#endif /* FIPS_NO_WRAPPERS */

#endif /* NO_RSA */


/* ECC API */
#ifdef HAVE_ECC

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_ECCKEY_TYPE_DEFINED
        typedef struct ecc_key ecc_key;
        #define WC_ECCKEY_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_ecc_init_fips(ecc_key* key);
    WOLFSSL_API int wc_ecc_free_fips(ecc_key* key);
    WOLFSSL_API int wc_ecc_set_rng_fips(ecc_key* key, WC_RNG* rng);
    WOLFSSL_API int wc_ecc_check_key_fips(ecc_key* key);
    WOLFSSL_API int wc_ecc_make_key_fips(WC_RNG* rng, int keysize,
                                         ecc_key* key);
    WOLFSSL_API int wc_ecc_make_key_ex_fips(WC_RNG* rng, int keysize,
                                            ecc_key* key, int curve_id);
    WOLFSSL_API int wc_ecc_export_x963_fips(ecc_key* key, byte* out,
                                            word32* outLen);
    WOLFSSL_API int wc_ecc_import_x963_fips(const byte* in, word32 inLen,
                                            ecc_key* key);
    WOLFSSL_API int wc_ecc_shared_secret_fips(
        ecc_key* private_key, ecc_key* public_key, byte* out, word32* outlen);
    WOLFSSL_API int wc_ecc_sign_hash_fips(const byte* in, word32 inlen,
                                          byte* out, word32* outlen,
                            WC_RNG* rng, ecc_key* key);
    WOLFSSL_API int wc_ecc_sign_hash_ex_fips(const byte* in, word32 inlen,
                             WC_RNG* rng, ecc_key* key, MP_INT_T* r, MP_INT_T* s);
    WOLFSSL_API int wc_ecc_verify_hash_fips(const byte* sig, word32 siglen,
        const byte* hash, word32 hashlen, int* res, ecc_key* key);
    WOLFSSL_API int wc_ecc_verify_hash_ex_fips(MP_INT_T* r, MP_INT_T* s, const byte* hash,
                            word32 hashlen, int* res, ecc_key* key);

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_ecc_init                 wc_ecc_init_fips
    #define wc_ecc_free                 wc_ecc_free_fips
    #define wc_ecc_set_rng              wc_ecc_set_rng_fips
    #define wc_ecc_check_key            wc_ecc_check_key_fips
    #define wc_ecc_make_key             wc_ecc_make_key_fips
    #define wc_ecc_make_key_ex          wc_ecc_make_key_ex_fips
    #define wc_ecc_export_x963          wc_ecc_export_x963_fips
    #define wc_ecc_import_x963          wc_ecc_import_x963_fips
    #define wc_ecc_shared_secret        wc_ecc_shared_secret_fips
    #define wc_ecc_sign_hash            wc_ecc_sign_hash_fips
    #define wc_ecc_sign_ex_hash         wc_ecc_sign_hash_ex_fips
    #define wc_ecc_verify_hash          wc_ecc_verify_hash_fips
    #define wc_ecc_verify_hash_ex       wc_ecc_verify_hash_ex_fips

    #define ecc_init_fips               wc_ecc_init_fips
    #define ecc_free_fips               wc_ecc_free_fips
    #define ecc_set_rng_fips            wc_ecc_set_rng_fips
    #define ecc_check_key_fips          wc_ecc_check_key_fips
    #define ecc_make_key_fips           wc_ecc_make_key_fips
    #define ecc_make_key_ex_fips        wc_ecc_make_key_ex_fips
    #define ecc_export_x963_fips        wc_ecc_export_x963_fips
    #define ecc_import_x963_fips        wc_ecc_import_x963_fips
    #define ecc_shared_secret_fips      wc_ecc_shared_secret_fips
    #define ecc_sign_hash_fips          wc_ecc_sign_hash_fips
    #define ecc_sign_hash_ex_fips       wc_ecc_sign_hash_ex_fips
    #define ecc_verify_hash_fips        wc_ecc_verify_hash_fips
    #define ecc_verify_hash_ex_fips     wc_ecc_verify_hash_ex_fips
#endif /* FIPS_NO_WRAPPERS */

#endif /* HAVE_ECC */


/* DH API */
#ifndef NO_DH

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_DH_TYPE_DEFINED
        typedef struct DhKey DhKey;
        #define WC_DH_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitDhKey_fips(DhKey* key);
    WOLFSSL_API int wc_FreeDhKey_fips(DhKey* key);
    WOLFSSL_API int wc_DhSetKeyEx_fips(
        DhKey* key, const byte* p, word32 pSz, const byte* g, word32 gSz,
        const byte* q, word32 qSz);
    WOLFSSL_API int wc_DhSetNamedKey_fips(DhKey* key, int name);
    WOLFSSL_API int wc_DhGenerateKeyPair_fips(
        DhKey* key, WC_RNG* rng, byte* priv, word32* privSz, byte* pub,
        word32* pubSz);
    WOLFSSL_API int wc_DhCheckPubKeyEx_fips(
        DhKey* key, const byte* pub, word32 pubSz, const byte* prime,
        word32 primeSz);
    WOLFSSL_API int wc_DhCheckPrivKeyEx_fips(
        DhKey* key, const byte* priv, word32 privSz, const byte* prime,
        word32 primeSz);
    WOLFSSL_API int wc_DhCheckKeyPair_fips(
        DhKey* key, const byte* pub, word32 pubSz, const byte* priv,
        word32 privSz);
    WOLFSSL_API int wc_DhAgree_fips(
        DhKey* key, byte* agree, word32* agreeSz, const byte* priv,
        word32 privSz, const byte* otherPub, word32 pubSz);

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitDhKey                wc_InitDhKey_fips
    #define wc_FreeDhKey                wc_FreeDhKey_fips
    #define wc_DhSetKey_ex              wc_DhSetKeyEx_fips
    #define wc_DhSetNamedKey            wc_DhSetNamedKey_fips
    #define wc_DhGenerateKeyPair        wc_DhGenerateKeyPair_fips
    #define wc_DhCheckPubKey_ex         wc_DhCheckPubKeyEx_fips
    #define wc_DhCheckPrivKey_ex        wc_DhCheckPrivKeyEx_fips
    #define wc_DhCheckKeyPair           wc_DhCheckKeyPair_fips
    #define wc_DhAgree                  wc_DhAgree_fips

    #define InitDhKey_fips              wc_InitDhKey_fips
    #define FreeDhKey_fips              wc_FreeDhKey_fips
    #define DhSetKey_ex_fips            wc_DhSetKeyEx_fips
    #define DhGenerateKeyPair_fips      wc_DhGenerateKeyPair_fips
    #define DhCheckPubKey_ex_fips       wc_DhCheckPubKeyEx_fips
    #define DhCheckPrivKey_ex_fips      wc_DhCheckPrivKeyEx_fips
    #define DhCheckKeyPair_fips         wc_DhCheckKeyPair_fips
    #define DhAgree_fips                wc_DhAgree_fips
#endif /* FIPS_NO_WRAPPERS */

#endif /* NO_DH */


/* SHA-1 API */
#ifndef NO_SHA

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_SHA_TYPE_DEFINED
        typedef struct wc_Sha wc_Sha;
        #define WC_SHA_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitSha_fips(wc_Sha* sha);
    WOLFSSL_API int wc_ShaUpdate_fips(wc_Sha* sha, const byte* data,
                                      word32 len);
    WOLFSSL_API int wc_ShaFinal_fips(wc_Sha* sha, byte* hash);
    WOLFSSL_API void wc_ShaFree_fips(wc_Sha* sha);

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitSha                  wc_InitSha_fips
    #define wc_ShaUpdate                wc_ShaUpdate_fips
    #define wc_ShaFinal                 wc_ShaFinal_fips
    #define wc_ShaFree                  wc_ShaFree_fips
    #define InitSha_fips                wc_InitSha_fips
    #define ShaUpdate_fips              wc_ShaUpdate_fips
    #define ShaFinal_fips               wc_ShaFinal_fips
    #define ShaFree_fips                wc_ShaFree_fips
#endif /* FIPS_NO_WRAPPERS */

#endif /* NO_SHA */


/* SHA-224 and SHA-256 API */
#ifndef NO_SHA256

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_SHA256_TYPE_DEFINED
        typedef struct wc_Sha256 wc_Sha256;
        #define WC_SHA256_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitSha256_fips(wc_Sha256* sha);
    WOLFSSL_API int wc_Sha256Update_fips(wc_Sha256* sha, const byte* data,
                                         word32 len);
    WOLFSSL_API int wc_Sha256Final_fips(wc_Sha256* sha, byte* hash);
    WOLFSSL_API void wc_Sha256Free_fips(wc_Sha256* sha);

    #ifdef WOLFSSL_SHA224
        #ifndef WC_SHA224_TYPE_DEFINED
            typedef struct wc_Sha256 wc_Sha224;
            #define WC_SHA224_TYPE_DEFINED
        #endif

        WOLFSSL_API int wc_InitSha224_fips(wc_Sha224* sha224);
        WOLFSSL_API int wc_Sha224Update_fips(wc_Sha224* sha224,
                                             const byte* data, word32 len);
        WOLFSSL_API int wc_Sha224Final_fips(wc_Sha224* sha224, byte* hash);
        WOLFSSL_API void wc_Sha224Free_fips(wc_Sha224* sha);
    #endif /* WOLFSSL_SHA224 */

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitSha256               wc_InitSha256_fips
    #define wc_Sha256Update             wc_Sha256Update_fips
    #define wc_Sha256Final              wc_Sha256Final_fips
    #define wc_Sha256Free               wc_Sha256Free_fips
    #define InitSha256_fips             wc_InitSha256_fips
    #define Sha256Update_fips           wc_Sha256Update_fips
    #define Sha256Final_fips            wc_Sha256Final_fips
    #define Sha256Free_fips             wc_Sha256Free_fips
    #ifdef WOLFSSL_SHA224
        #define wc_InitSha224           wc_InitSha224_fips
        #define wc_Sha224Update         wc_Sha224Update_fips
        #define wc_Sha224Final          wc_Sha224Final_fips
        #define wc_Sha224Free           wc_Sha224Free_fips
        #define InitSha224_fips         wc_InitSha224_fips
        #define Sha224Update_fips       wc_Sha224Update_fips
        #define Sha224Final_fips        wc_Sha224Final_fips
        #define Sha224Free_fip          wc_Sha224Free_fips
    #endif /* WOLFSSL_SHA224 */
#endif /* FIPS_NO_WRAPPERS */

#endif /* NO_SHA256 */


/* SHA-384 and SHA-512 API */
#ifndef NO_SHA512

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_SHA512_TYPE_DEFINED
        typedef struct wc_Sha512 wc_Sha512;
        #define WC_SHA512_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitSha512_fips(wc_Sha512* sha);
    WOLFSSL_API int wc_Sha512Update_fips(wc_Sha512* sha, const byte* data,
                                         word32 len);
    WOLFSSL_API int wc_Sha512Final_fips(wc_Sha512* sha, byte* hash);
    WOLFSSL_API void wc_Sha512Free_fips(wc_Sha512* sha);

    #ifdef WOLFSSL_SHA384
        #ifndef WC_SHA384_TYPE_DEFINED
            typedef struct wc_Sha512 wc_Sha384;
            #define WC_SHA384_TYPE_DEFINED
        #endif
        WOLFSSL_API int wc_InitSha384_fips(wc_Sha384* sha);
        WOLFSSL_API int wc_Sha384Update_fips(wc_Sha384* sha, const byte* data,
                                             word32 len);
        WOLFSSL_API int wc_Sha384Final_fips(wc_Sha384* sha, byte* hash);
        WOLFSSL_API void wc_Sha384Free_fips(wc_Sha384* sha);
    #endif /* WOLFSSL_SHA384 */

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitSha512               wc_InitSha512_fips
    #define wc_Sha512Update             wc_Sha512Update_fips
    #define wc_Sha512Final              wc_Sha512Final_fips
    #define wc_Sha512Free               wc_Sha512Free_fips
    #define InitSha512_fips             wc_InitSha512_fips
    #define Sha512Update_fips           wc_Sha512Update_fips
    #define Sha512Final_fips            wc_Sha512Final_fips
    #define Sha512Free_fips             wc_Sha512Free_fips
    #ifdef WOLFSSL_SHA384
        #define wc_InitSha384           wc_InitSha384_fips
        #define wc_Sha384Update         wc_Sha384Update_fips
        #define wc_Sha384Final          wc_Sha384Final_fips
        #define wc_Sha384Free           wc_Sha384Free_fips
        #define InitSha384_fips         wc_InitSha384_fips
        #define Sha384Update_fips       wc_Sha384Update_fips
        #define Sha384Final_fips        wc_Sha384Final_fips
        #define Sha384Free_fips         wc_Sha384Free_fips
    #endif /* WOLFSSL_SHA384 */
#endif /* FIPS_NO_WRAPPERS */

#endif /* NO_SHA512 */


/* SHA-3 API */
#ifdef WOLFSSL_SHA3

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_SHA3_TYPE_DEFINED
        typedef struct wc_Sha3 wc_Sha3;
        #define WC_SHA3_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitSha3_224_fips(wc_Sha3* sha3, void* heap, int devId);
    WOLFSSL_API int wc_Sha3_224_Update_fips(wc_Sha3* sha3, const byte* data,
                                            word32 len);
    WOLFSSL_API int wc_Sha3_224_Final_fips(wc_Sha3* sha3, byte* hash);
    WOLFSSL_API void wc_Sha3_224_Free_fips(wc_Sha3* sha3);

    WOLFSSL_API int wc_InitSha3_256_fips(wc_Sha3* sha3, void* heap, int devId);
    WOLFSSL_API int wc_Sha3_256_Update_fips(wc_Sha3* sha3, const byte* data,
                                            word32 len);
    WOLFSSL_API int wc_Sha3_256_Final_fips(wc_Sha3* sha3, byte* hash);
    WOLFSSL_API void wc_Sha3_256_Free_fips(wc_Sha3* sha3);

    WOLFSSL_API int wc_InitSha3_384_fips(wc_Sha3* sha3, void* heap, int devId);
    WOLFSSL_API int wc_Sha3_384_Update_fips(wc_Sha3* sha3, const byte* data,
                                            word32 len);
    WOLFSSL_API int wc_Sha3_384_Final_fips(wc_Sha3* sha3, byte* hash);
    WOLFSSL_API void wc_Sha3_384_Free_fips(wc_Sha3* sha3);

    WOLFSSL_API int wc_InitSha3_512_fips(wc_Sha3* sha3, void* heap, int devId);
    WOLFSSL_API int wc_Sha3_512_Update_fips(wc_Sha3* sha3, const byte* data,
                                            word32 len);
    WOLFSSL_API int wc_Sha3_512_Final_fips(wc_Sha3* sha3, byte* hash);
    WOLFSSL_API void wc_Sha3_512_Free_fips(wc_Sha3* sha3);

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitSha3_224             wc_InitSha3_224_fips
    #define wc_Sha3_224_Update          wc_Sha3_224_Update_fips
    #define wc_Sha3_224_Final           wc_Sha3_224_Final_fips
    #define wc_Sha3_224_Free            wc_Sha3_224_Free_fips
    #define wc_InitSha3_256             wc_InitSha3_256_fips
    #define wc_Sha3_256_Update          wc_Sha3_256_Update_fips
    #define wc_Sha3_256_Final           wc_Sha3_256_Final_fips
    #define wc_Sha3_256_Free            wc_Sha3_256_Free_fips
    #define wc_InitSha3_384             wc_InitSha3_384_fips
    #define wc_Sha3_384_Update          wc_Sha3_384_Update_fips
    #define wc_Sha3_384_Final           wc_Sha3_384_Final_fips
    #define wc_Sha3_384_Free            wc_Sha3_384_Free_fips
    #define wc_InitSha3_512             wc_InitSha3_512_fips
    #define wc_Sha3_512_Update          wc_Sha3_512_Update_fips
    #define wc_Sha3_512_Final           wc_Sha3_512_Final_fips
    #define wc_Sha3_512_Free            wc_Sha3_512_Free_fips

    #define InitSha3_224_fips           wc_InitSha3_224_fips
    #define Sha3_224_Update_fips        wc_Sha3_224_Update_fips
    #define Sha3_224_Final_fips         wc_Sha3_224_Final_fips
    #define Sha3_224_Free_fips          wc_Sha3_224_Free_fips
    #define InitSha3_256_fips           wc_InitSha3_256_fips
    #define Sha3_256_Update_fips        wc_Sha3_256_Update_fips
    #define Sha3_256_Final_fips         wc_Sha3_256_Final_fips
    #define Sha3_256_Free_fips          wc_Sha3_256_Free_fips
    #define InitSha3_384_fips           wc_InitSha3_384_fips
    #define Sha3_384_Update_fips        wc_Sha3_384_Update_fips
    #define Sha3_384_Final_fips         wc_Sha3_384_Final_fips
    #define Sha3_384_Free_fips          wc_Sha3_384_Free_fips
    #define InitSha3_512_fips           wc_InitSha3_512_fips
    #define Sha3_512_Update_fips        wc_Sha3_512_Update_fips
    #define Sha3_512_Final_fips         wc_Sha3_512_Final_fips
    #define Sha3_512_Free_fips          wc_Sha3_512_Free_fips
#endif /* FIPS_NO_WRAPPERS */

#endif /* WOLFSSL_SHA3 */


/* HMAC API */
#ifndef NO_HMAC

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_HMAC_TYPE_DEFINED
        typedef struct Hmac Hmac;
        #define WC_HMAC_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_HmacSetKey_fips(Hmac* hmac, int type, const byte* key,
                                       word32 keySz);
    WOLFSSL_API int wc_HmacUpdate_fips(Hmac* hmac, const byte* data,
                                       word32 len);
    WOLFSSL_API int wc_HmacFinal_fips(Hmac* hmac, byte* hash);
    WOLFSSL_API void wc_HmacFree_fips(Hmac* hmac);

    #ifdef WOLFSSL_HAVE_PRF
        WOLFSSL_API int wc_PRF_fips(byte* result, word32 resLen,
            const byte* secret, word32 secLen,
            const byte* seed, word32 seedLen,
            int hash_type, void* heap, int devId);
        WOLFSSL_API int wc_PRF_TLSv12_fips(byte* result, word32 resLen,
            const byte* secret, word32 secLen,
            const byte* label, word32 labLen,
            const byte* seed, word32 seedLen,
            int useAtLeastSha256, int hash_type,
            void* heap, int devId);
    #endif /* WOLFSSL_HAVE_PRF */

    #ifdef HAVE_HKDF
        WOLFSSL_API int wc_HKDF_Extract_fips(int type,
                const byte* salt, word32 saltSz,
                const byte* inKey, word32 inKeySz, byte* out);
        WOLFSSL_API int wc_HKDF_Expand_fips(int type,
                const byte* inKey, word32 inKeySz,
                const byte* info, word32 infoSz,
                byte* out, word32 outSz);
        WOLFSSL_API int wc_HKDF_fips(int type,
                const byte* inKey, word32 inKeySz,
                const byte* salt, word32 saltSz,
                const byte* info, word32 infoSz,
                byte* out, word32 outSz);
        WOLFSSL_API int wc_Tls13_HKDF_Extract_fips(byte* prk,
                const byte* salt, int saltLen,
                byte* ikm, int ikmLen, int digest);
        WOLFSSL_API int wc_Tls13_HKDF_Expand_Label_fips(
                byte* okm, word32 okmLen,
                const byte* prk, word32 prkLen,
                const byte* protocol, word32 protocolLen,
                const byte* label, word32 labelLen,
                const byte* info, word32 infoLen,
                int digest);
    #endif /* HAVE_HKDF */

    #ifdef WOLFSSL_WOLFSSH
        WOLFSSL_API int wc_SSH_KDF_fips(byte hashId, byte keyId,
                byte* key, word32 keySz,
                const byte* k, word32 kSz,
                const byte* h, word32 hSz,
                const byte* sessionId, word32 sessionIdSz);
    #endif /* WOLFSSL_WOLFSSH */

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_HmacSetKey               wc_HmacSetKey_fips
    #define wc_HmacUpdate               wc_HmacUpdate_fips
    #define wc_HmacFinal                wc_HmacFinal_fips
    #define wc_HmacFree                 wc_HmacFree_fips
    #define HmacSetKey_fips             wc_HmacSetKey_fips
    #define HmacUpdate_fips             wc_HmacUpdate_fips
    #define HmacFinal_fips              wc_HmacFinal_fips
    #define HmacFree_fips               wc_HmacFree_fips
    #ifdef WOLFSSL_HAVE_PRF
        #define wc_PRF                  wc_PRF_fips
        #define wc_PRF_TLS              wc_PRF_TLSv12_fips
    #endif /* WOLFSSL_HAVE_PRF */

    #ifdef HAVE_HKDF
        #define wc_HKDF_Extract         wc_HKDF_Extract_fips
        #define wc_HKDF_Expand          wc_HKDF_Expand_fips
        #define wc_HKDF                 wc_HKDF_fips
        #define HKDF_fips               wc_HKDF_fips
        #define wc_Tls13_HKDF_Extract   wc_Tls13_HKDF_Extract_fips
        #define wc_Tls13_HKDF_Expand_Label wc_Tls13_HKDF_Expand_Label_fips
    #endif /* HAVE_HKDF */

    #ifdef WOLFSSL_WOLFSSH
        #define wc_SSH_KDF              wc_SSH_KDF_fips
    #endif /* WOLFSSL_WOLFSSH */
#endif /* FIPS_NO_WRAPPERS */

#endif /* NO_HMAC */


/* CMAC API */
#ifdef WOLFSSL_CMAC

#ifdef FIPS_NO_WRAPPERS
    #ifndef WC_CMAC_TYPE_DEFINED
        typedef struct Cmac Cmac;
        #define WC_CMAC_TYPE_DEFINED
    #endif

    WOLFSSL_API int wc_InitCmac_fips(Cmac* cmac, const byte* key, word32 keySz,
                                     int type, void* unused);
    WOLFSSL_API int wc_CmacUpdate_fips(Cmac* cmac, const byte* in, word32 inSz);
    WOLFSSL_API int wc_CmacFinal_fips(Cmac* cmac, byte* out, word32* outSz);

#else /* FIPS_NO_WRAPPERS */
    /* if not impl or fips.c impl wrapper force fips calls if fips build */
    #define wc_InitCmac                 wc_InitCmac_fips
    #define wc_CmacUpdate               wc_CmacUpdate_fips
    #define wc_CmacFinal                wc_CmacFinal_fips

    #define InitCmac_fips               wc_InitCmac_fips
    #define CmacUpdate_fips             wc_CmacUpdate_fips
    #define CmacFinal_fips              wc_CmacFinal_fips
#endif /* FIPS_NO_WRAPPERS */

#endif /* WOLFSSL_CMAC */


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_FIPS_H */

