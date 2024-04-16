/* fips.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* in case user set HAVE_FIPS there */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_FIPS

#ifdef USE_WINDOWS_API
    #pragma code_seg(".fipsA$o")
    #pragma const_seg(".fipsB$o")
#endif

/* detect new macro for disabling RNG */
#if defined(WC_NO_RNG) && !defined(NO_RNG)
    #define NO_RNG
#endif


/* set FIPS_NO_WRAPPERS before headers, use direct internal f()s not wrappers */
#define FIPS_NO_WRAPPERS

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/fips_test.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif


#if defined(HAVE_FORCE_FIPS_FAILURE) || defined(DEBUG_WOLFSSL)
    #include <stdio.h>
    static void FIPS_MSG(const char* msg)
    {
        printf("%s\n", msg);
    }
#else
    #define FIPS_MSG(m)
#endif

#ifdef WOLFSSL_STM32L4
    extern HAL_StatusTypeDef HAL_Init(void);
    extern void wolfSSL_POS_SystemClock_Config(void);
#endif /* WOLFSSL_STM32L4 */


#ifdef USE_WINDOWS_API

    #define CCALL __cdecl
    #pragma section(".CRT$XCU",read)
    #define INITIALIZER(f) \
       static void __cdecl f(void); \
       __declspec(allocate(".CRT$XCU")) void (__cdecl*f##_)(void) = f; \
       static void __cdecl f(void)

#elif defined(NO_ATTRIBUTE_CONSTRUCTOR)

    #define INITIALIZER(f) void f(void)

#else

    #define INITIALIZER(f) static void __attribute__((constructor)) f(void)

#endif


/* power on self (pos) test status */
enum POS_STATUS {
    POS_NOT_DONE,    /* in progress, not complete yet */
    POS_FAILURE,     /* done, but failed  */
    POS_SUCCESS      /* done, and SUCCESS */
};

static enum POS_STATUS posStatus = POS_NOT_DONE;   /* our pos status */
static int             posReturn = 0;              /* pos return value */
static char base16_hash[FIPS_IN_CORE_DIGEST_SIZE*2+1]; /* calculated hash */


fipsCastStateId_t fipsCastStatus[FIPS_CAST_COUNT];
enum FipsModeId fipsMode;


#ifdef WOLFSSL_FIPS_DEBUG_OUTPUT

    static const char* CastIdToStr(enum FipsCastId id)
    {
        switch (id) {
            case FIPS_CAST_AES_CBC:
                return "AES-CBC";
            case FIPS_CAST_AES_GCM:
                return "AES-GCM";
            case FIPS_CAST_HMAC_SHA1:
                return "HMAC-SHA1";
            case FIPS_CAST_HMAC_SHA2_256:
                return "HMAC-SHA2-256";
            case FIPS_CAST_HMAC_SHA2_512:
                return "HMAC-SHA2-512";
            case FIPS_CAST_HMAC_SHA3_256:
                return "HMAC-SHA3-256";
            case FIPS_CAST_DRBG:
                return "DRBG";
            case FIPS_CAST_RSA_SIGN_PKCS1v15:
                return "RSA Sign PKCS1 v1.5";
            case FIPS_CAST_ECC_CDH:
                return "ECC Cofactor";
            case FIPS_CAST_ECC_PRIMITIVE_Z:
                return "ECC Primitive Z";
            case FIPS_CAST_DH_PRIMITIVE_Z:
                return "DH Primitive Z";
            case FIPS_CAST_ECDSA:
                return "ECDSA";
            case FIPS_CAST_KDF_TLS12:
                return "KDF-TLS12";
            case FIPS_CAST_KDF_TLS13:
                return "KDF-TLS13";
            case FIPS_CAST_KDF_SSH:
                return "KDF-SSH";
            case FIPS_CAST_COUNT:
                return "count";
            default:
                return "unknown";
        }
    }


    static const char* CastStateIdToStr(fipsCastStateId_t id)
    {
        switch (fipsCastStatus_get(id)) {
            case FIPS_CAST_STATE_INIT:
                return "initialized";
            case FIPS_CAST_STATE_PROCESSING:
                return "processing";
            case FIPS_CAST_STATE_SUCCESS:
                return "success";
            case FIPS_CAST_STATE_FAILURE:
                return "failure";
            default:
                return "unknown";
        }
    }


    static void OutputCastStatus(void)
    {
        int i;

        for (i = 0; i < FIPS_CAST_COUNT; i++) {
            printf("%20s test: %s\n",
                    CastIdToStr((enum FipsCastId)i),
                    CastStateIdToStr(fipsCastStatus[i]));
        }
    }
    #define OUTPUT_CAST_STATUS() do { OutputCastStatus(); } while(0)

#else
    #define OUTPUT_CAST_STATUS() do {} while(0)
#endif


/*
 * HAVE_THREAD_LS: means compiler provides a primitive local storage type.
 *
 * NO_THREAD_LS: works in SINGLE_THREADED mode OR where the compiler doesn't
 * provide local storage. It MUST be guaranteed that this is run in a single
 * task/thread and we are absolutely certain no other task/thread can access
 * the wolfcrypt module before execution of the power on self test has finished.
 * Note GetTLS(&thisThreadInPOS) MUST return correct value therefore no ops
 * would not work.
 */
#ifdef WOLFSSL_LINUXKM
    typedef atomic_t TLS_Key;

    static INLINE int InitTLS(TLS_Key* key)
    {
        atomic_set(key, 0);
        return 0;
    }

    static INLINE int GetTLS(TLS_Key* key)
    {
        return atomic_read(key);
    }

    /* for the linuxkm, there is no true TLS (indeed some contexts aren't
     * associated with a thread), so use the variable as a mutex.
     */
    static WARN_UNUSED_RESULT INLINE int SetTLS(TLS_Key* key, int cur_flag, int next_flag)
    {
        int cmpxchg_ret = atomic_cmpxchg(key, cur_flag, next_flag);
        if (cmpxchg_ret == cur_flag)
            return 0;
        else
            return -1;
    }

#elif defined(HAVE_THREAD_LS) || defined(NO_THREAD_LS)
    /* Note: this thread local stuff doesn't work in pre-Vista DLLs.
     * Need to use TlsAlloc, etc, in that case. */

    typedef int TLS_Key;

    static INLINE int InitTLS(TLS_Key* key)
    {
        *key = 0;
        return 0;
    }

    static INLINE int GetTLS(TLS_Key* key)
    {
        return *key;
    }

    static INLINE void SetTLS(TLS_Key* key, int flag)
    {
        *key = flag;
    }

#elif defined(USE_WINDOWS_API)
    /* Uses the WINAPI calls that TlsAlloc() the thread local
     * storage rather than using the _declspec(thread) tags.
     * pre-Vista DLLs, and DLLs loaded at runtime cannot use
     * the declspec tag. */

    typedef DWORD TLS_Key;

    static INLINE int NewTLS(TLS_Key* key)
    {
        *key = TlsAlloc();
        if (*key == TLS_OUT_OF_INDEXES)
            return THREAD_STORE_KEY_E;

        return 0;
    }

    static INLINE int InitTLS(TLS_Key* key)
    {
        int* value;

        value = (int*)malloc(sizeof(int));
        if (value == NULL)
            return MEMORY_E;

        *value = 0;

        if (TlsSetValue(*key, (LPVOID)value) == 0) {
            free(value);
            return THREAD_STORE_SET_E;
        }

        return 0;
    }

    static INLINE int GetTLS(TLS_Key* key)
    {
        int* value = TlsGetValue(*key);

        if (value != NULL)
            return *value;
        else 
            return InitTLS(key);

        return 0;
    }

    static INLINE void SetTLS(TLS_Key* key, int flag)
    {
        int* value = TlsGetValue(*key);

        if (value != NULL)
            *value = flag;
        else {
            if (InitTLS(key) == 0) {
                SetTLS(key, flag);
            }
        }
    }

    static INLINE void FreeTLS(TLS_Key* key)
    {
        int* value = TlsGetValue(*key);

        if (value != NULL)
            free(value);
        TlsFree(*key);
    }

#else

    typedef pthread_key_t TLS_Key;

    static INLINE int NewTLS(TLS_Key* key)
    {
        if (pthread_key_create(key, NULL) != 0)
            return THREAD_STORE_KEY_E;

        return 0;
    }

    static INLINE int InitTLS(TLS_Key* key)
    {
        int* value;

        value = (int*)malloc(sizeof(int));
        if (value == NULL)
            return MEMORY_E;

        *value = 0;

        if (pthread_setspecific(*key, value) != 0) {
            free(value);
            return THREAD_STORE_SET_E;
        }

        return 0;
    }

    static INLINE int GetTLS(TLS_Key* key)
    {
        int* value = pthread_getspecific(*key);

        if (value != NULL)
            return *value;
        else 
            return InitTLS(key);

        return 0;
    }

    static INLINE void SetTLS(TLS_Key* key, int flag)
    {
        int* value = pthread_getspecific(*key);

        if (value != NULL)
            *value = flag;
        else {
             if (InitTLS(key) == 0) {
                SetTLS(key, flag);
            }
        }
    }

#endif

#ifdef WOLFSSL_LINUXKM
static THREAD_LS_T TLS_Key thisThreadInPOS = ATOMIC_INIT(0);          /* one per kernel module */
static THREAD_LS_T TLS_Key privateKeyReadEnable = ATOMIC_INIT(0);     /* one per kernel module, default to false */
#else
static THREAD_LS_T TLS_Key thisThreadInPOS = 0;          /* per thread in pos */
static THREAD_LS_T TLS_Key privateKeyReadEnable = 0;     /* default to false */
#endif


#ifndef NO_RNG
static wolfSSL_Mutex conTestMutex;       /* continuous test mutex */
static int           conTestFailure = 0; /* in failure mode */
#endif

wolfCrypt_fips_cb errCb = NULL;                    /* error callback */

/* user callback setter for err result */
int wolfCrypt_SetCb_fips(wolfCrypt_fips_cb cbf)
{
    errCb = cbf;

    return 0;
}


/* check continuous test status, return 0 if status ok, else < 0 */
#ifndef NO_RNG
static int CheckConTestStatus(void)
{
    int localFailure = 0;

    if (LockMutex(&conTestMutex) != 0) {
        conTestFailure = 1;
        localFailure   = 1;
    } else {
        if (conTestFailure)
            localFailure = 1;
        UnLockMutex(&conTestMutex);
    }

    if (localFailure) {
        return -1;
    }

    return 0;
}
#endif

/* set continuous test failure status, return 0 on success */
#ifndef NO_RNG
static int SetConTestFailure(void)
{
    if (LockMutex(&conTestMutex) != 0) {
        conTestFailure = 1;
    } else {
        conTestFailure = 1;
        UnLockMutex(&conTestMutex);
    }

    return 0;
}
#endif

/* // NOLINTBEGIN(misc-no-recursion) */

static void EnterDegradedMode(int castErr)
{
    int i, ret;

    if (fipsMode == FIPS_MODE_DEGRADED) {
#ifdef DEBUG_FIPS_VERBOSE
        FIPS_MSG("Module already in degraded mode, do nothing");
#endif
        (void) i;
        (void) ret;
    } else {

        FIPS_MSG("Enter EnterDegradedMode()");
        if (errCb) {
            errCb(0, castErr, base16_hash);
        }
        fipsMode = FIPS_MODE_DEGRADED;
        for (i = 0; i < FIPS_CAST_COUNT; i++) {
            if (fipsCastStatus_get(i) == FIPS_CAST_STATE_SUCCESS) {
                fipsCastStatus_put(i, FIPS_CAST_STATE_INIT);
            }
        }
        if (errCb) {
            errCb(1, FIPS_DEGRADED_E, base16_hash);
        }

        ret = wc_RunAllCast_fips();
        if (ret == 0) {
            FIPS_MSG("ERROR: All casts passed in degraded mode\n");
            FIPS_MSG("ERROR: Reload the module or power cycle the device\n");
            posStatus = POS_FAILURE;
            posReturn = FIPS_NOT_ALLOWED_E;
        }


        FIPS_MSG("Leave EnterDegradedMode()");
    }
}

int wolfCrypt_GetMode_fips(void)
{
    return (int)fipsMode;
}


#ifdef HAVE_FORCE_FIPS_FAILURE

#define DEGRADE_STATE(a) { fipsCastStatus[a] = FIPS_CAST_STATE_PROCESSING; \
                           fipsCastStatus_put(a, FIPS_CAST_STATE_FAILURE); }

int wolfCrypt_SetStatus_fips(int status)
{
    if (status == DRBG_CONT_FIPS_E) {
#ifndef NO_RNG
        SetConTestFailure();
        return 0;
#else
        return NOT_COMPILED_IN;
#endif
    } else if (status < 0) {
        printf("Setting status: %s\n", wc_GetErrorString(status));
        switch(status) {
            /* -203 */
            case IN_CORE_FIPS_E:
                posStatus = POS_FAILURE;
                fipsMode = FIPS_MODE_FAILED;
                posReturn = status; break;
            /* -204 */
            case AES_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_AES_GCM);
                DEGRADE_STATE(FIPS_CAST_AES_CBC); break;
            /* -205 - Des3 not supported in 140-3 or degraded mode*/
            case DES3_KAT_FIPS_E:
                FIPS_MSG("Des3 not supported in this module, no change");
                return 0;
            /* -206 */
            case HMAC_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_HMAC_SHA1);
                DEGRADE_STATE(FIPS_CAST_HMAC_SHA2_256);
                DEGRADE_STATE(FIPS_CAST_HMAC_SHA2_512);
                DEGRADE_STATE(FIPS_CAST_HMAC_SHA3_256); break;
            /* -207 */
            case RSA_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_RSA_SIGN_PKCS1v15); break;
            /* -208 */
            case DRBG_KAT_FIPS_E:
                /* fall-through to -209 */
            /* -209 */
            case DRBG_CONT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_DRBG); break;
            /* -210 */
            case AESGCM_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_AES_GCM); break;
            /* -242 */
            case ECC_CDH_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_ECC_CDH); break;
            /* -254 - There is no RSA-PSS PAT test, defer to -207 */
            case RSAPSS_PAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_RSA_SIGN_PKCS1v15); break;
            /* -255 - There is no ECDSA PAT test, defer to -280 */
            case ECDSA_PAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_ECDSA); break;
            /* -256 */
            case DH_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_DH_PRIMITIVE_Z); break;
            /* -257 There is no CCM KAT, defer to AES -204 */
            case AESCCM_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_AES_GCM);
                DEGRADE_STATE(FIPS_CAST_AES_CBC); break;
            /* -258 - SHA3 is tested as part of a higher level protocol under
             *        HMAC, there is no specific SHA3 KAT to fail, defer to
             *        HMAC-SHA3 KAT */
            case SHA3_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_HMAC_SHA3_256); break;
            /* -259 */
            case ECDHE_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_ECC_PRIMITIVE_Z); break;
            /* -280 */
            case ECDSA_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_ECDSA); break;
            /* -281 */
            case RSA_PAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_RSA_SIGN_PKCS1v15); break;
            /* -282 */
            case KDF_TLS12_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_KDF_TLS12); break;
            /* -283 */
            case KDF_TLS13_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_KDF_TLS13); break;
            /* -284 */
            case KDF_SSH_KAT_FIPS_E:
                DEGRADE_STATE(FIPS_CAST_KDF_SSH); break;
            /* -285 - There is no DHE Pairwise Consistency test, defer to -256*/
            case DHE_PCT_E:
                DEGRADE_STATE(FIPS_CAST_DH_PRIMITIVE_Z); break;
            /* -286 - There is no ECC Pairwise Consistency test, defer to -259*/
            case ECC_PCT_E:
                DEGRADE_STATE(FIPS_CAST_ECC_PRIMITIVE_Z); break;
            /* -287 - Degrade all private key services */
            case FIPS_PRIVATE_KEY_LOCKED_E:
                DEGRADE_STATE(FIPS_CAST_RSA_SIGN_PKCS1v15);
                DEGRADE_STATE(FIPS_CAST_ECDSA);
                DEGRADE_STATE(FIPS_CAST_DH_PRIMITIVE_Z); break;
            /* -298 - This is just degraded mode, do nothing */
            default:
                FIPS_MSG("That code has no impact on the module, do nothing");
                return 0;
        }
        if (posReturn == 0) {
            EnterDegradedMode(status);
            posStatus = POS_SUCCESS;
        }
        return 0;
    }

    return BAD_FUNC_ARG;
}

#endif /* HAVE_FORCE_FIPS_FAILURE */


/* return 0 on allowed (success), < 0 on error */
static int FipsAllowed(void)
{
    if (posStatus == POS_NOT_DONE && GetTLS(&thisThreadInPOS) == 1)
        return 0;  /* allow POS on this thread only */
    else if (posStatus == POS_FAILURE) {
        if (errCb)
            errCb(0, posReturn, base16_hash);
        return -1;
    }

#ifndef NO_RNG
    if (CheckConTestStatus() != 0) {
        if (errCb)
            errCb(0, DRBG_CONT_FIPS_E, base16_hash);
        return -1;
    }
#endif

    return 0;
}


/* return 0 on allowed (success), < 0 on error */
static int AlgoAllowed(int type)
{
    int castErr = 0;

    if ((type < 0) || (type >= FIPS_CAST_COUNT)) {
        return -1;
    }

    if (fipsCastStatus_get(type) == FIPS_CAST_STATE_SUCCESS) {
        return 0;
    }

#ifdef WOLFSSL_LINUXKM
    /* for CAST in _LINUXKM, atomic ops are used for safe contended access to
     * fipsCastStatus[type], and thisThreadInPOS isn't used at all.
     */
    castErr = DoCAST(type);
    if (castErr == 0)
        return 0;
    else {
        EnterDegradedMode(castErr);
        return -1;
    }
#else /* !WOLFSSL_LINUXKM */
    if (GetTLS(&thisThreadInPOS) > 0) {
        if (fipsCastStatus_get(type) == FIPS_CAST_STATE_PROCESSING) {
            return 0;
        }
        else if (fipsCastStatus_get(type) == FIPS_CAST_STATE_INIT) {
            /* This is happening because another CAST is in process,
             * and this algo is a dependency. */
            castErr = DoCAST(type);
        }
    }

    if (fipsCastStatus_get(type) == FIPS_CAST_STATE_INIT) {
        SetTLS(&thisThreadInPOS, 1);
        castErr = DoCAST(type);
        SetTLS(&thisThreadInPOS, 0);
    }

    /* Return test status */
    if (fipsCastStatus_get(type) == FIPS_CAST_STATE_SUCCESS) {
        return 0;
    }
    else {
        EnterDegradedMode(castErr);
        return -1;
    }
#endif /* !WOLFSSL_LINUXKM */
}


/* power on self test proper, only function to change POS status, only called
 * by entry point */
static void DoSelfTest(void)
{
#ifdef WOLFSSL_LINUXKM
    if (SetTLS(&thisThreadInPOS, 0, 1) < 0) {
        pr_err("FIPS error: POS initiated, but thisThreadInPOS already has value %d.\n",GetTLS(&thisThreadInPOS));
    }
#else
    SetTLS(&thisThreadInPOS, 1);
#endif

    FIPS_MSG("Starting Power On Self Test");

    /* switch to not done, mark this thread as in pos */
    posStatus = POS_NOT_DONE;
    fipsMode = FIPS_MODE_INIT;

    /* do tests proper */
    if ( (posReturn = DoPOST(base16_hash, sizeof(base16_hash))) != 0) {
        OUTPUT_CAST_STATUS();
        posStatus = POS_FAILURE;
        fipsMode = FIPS_MODE_FAILED;
#ifdef WOLFSSL_LINUXKM
        if (SetTLS(&thisThreadInPOS, 1, 0) < 0)
            pr_err("FIPS error: thisThreadInPOS should be 1, but is %d.\n",GetTLS(&thisThreadInPOS));
#else
        SetTLS(&thisThreadInPOS, 0);
#endif
        FIPS_MSG("Pre-Operational Self Test FAILURE");
        return;
    }
    ForceZero(base16_hash, sizeof(base16_hash));
    OUTPUT_CAST_STATUS();

    /* completed success */
    posStatus = POS_SUCCESS;
    fipsMode = FIPS_MODE_NORMAL;
#ifdef WOLFSSL_LINUXKM
        if (SetTLS(&thisThreadInPOS, 1, 0) < 0) {
            pr_err("FIPS error: thisThreadInPOS should be 1, but is %d.\n",GetTLS(&thisThreadInPOS));
        }
#else
        SetTLS(&thisThreadInPOS, 0);
#endif

    FIPS_MSG("Pre-Operational Self Test SUCCESS");
}


/* fips entry point, auto */
INITIALIZER(fipsEntry)
{
#ifdef WOLFSSL_STM32L4
    /* Configure clock peripheral at 120MHz otherwise the tests take
     * more than 12 minutes to complete. With peripheral configured
     * takes 32 seconds */
    HAL_Init();
    wolfSSL_POS_SystemClock_Config();
#endif
#ifndef NO_RNG
    if (InitMutex(&conTestMutex) != 0) {
        conTestFailure = 1;
    }
#endif

#if !defined(HAVE_THREAD_LS) && !defined(NO_THREAD_LS)
    /* In the case of TlsAlloc() or pthread_key_create use case,
    *  (no __thread or __declspec(thread))
    *  it needs allocating a TLS index or pthread key.
    *  then any threads init TLS index for itself by calling InitTLS().
    *  GetTLS()/SetTLS() call initTLS if the index is not initialized for
    *  the thread.
    */
    if (NewTLS(&thisThreadInPOS) != 0) {
        posStatus = POS_FAILURE;
        FIPS_MSG("Power On Self Test FAILURE");
        return;
    }

    if (NewTLS(&privateKeyReadEnable) != 0) {
        posStatus = POS_FAILURE;
        FIPS_MSG("Power On Self Test FAILURE");
        return;
    }
#endif
    if ( (posReturn = InitTLS(&thisThreadInPOS)) != 0) {
        posStatus = POS_FAILURE;
        FIPS_MSG("Power On Self Test FAILURE");
        return;
    }

    if ( (posReturn = InitTLS(&privateKeyReadEnable)) != 0) {
        posStatus = POS_FAILURE;
        FIPS_MSG("Power On Self Test FAILURE");
        return;
    }

    DoSelfTest();
}


#if defined(USE_WINDOWS_API) && defined(WOLFSSL_DLL)

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved )
{
    (void)hinstDLL;
    (void)lpReserved;

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            fipsEntry();
            break;
        case DLL_PROCESS_DETACH:
            #if !defined(HAVE_THREAD_LS) && !defined(NO_THREAD_LS)
                FreeTLS(&thisThreadInPOS);
                FreeTLS(&privateKeyReadEnable);
            #endif
            break;
#if !defined(HAVE_THREAD_LS) && !defined(NO_THREAD_LS)
        case DLL_THREAD_ATTACH:
            if ((posReturn = InitTLS(&thisThreadInPOS)) != 0) {
                posStatus = POS_FAILURE;
                FIPS_MSG("Init TLS index for thread failure");
            }
            if ((posReturn = InitTLS(&privateKeyReadEnable)) != 0) {
                posStatus = POS_FAILURE;
                FIPS_MSG("Init TLS index for thread failure");
            }
            break;
        case DLL_THREAD_DETACH:
            FreeTLS(&thisThreadInPOS);
            FreeTLS(&privateKeyReadEnable);
            break;
#endif
    }

    return TRUE;
}

#endif


#ifdef WOLFSSL_LINUXKM

int wolfCrypt_SetPrivateKeyReadEnable_fips(int enable, enum wc_KeyType keyType)
{
    if (keyType == WC_KEYTYPE_ALL) {
        if (enable == 0) {
            if (atomic_dec_return(&privateKeyReadEnable) < 0) {
                atomic_inc(&privateKeyReadEnable);
                return BAD_STATE_E;
            }
            return 0;
        }
        else {
            int cur_privateKeyReadEnable = atomic_read(&privateKeyReadEnable);
            for (;;) {
                int cmpxchg_ret;
                if (cur_privateKeyReadEnable >= INT_MAX)
                    return BAD_STATE_E;
                cmpxchg_ret = atomic_cmpxchg(&privateKeyReadEnable, cur_privateKeyReadEnable, cur_privateKeyReadEnable + 1);
                if (cmpxchg_ret == cur_privateKeyReadEnable)
                    return 0;
                cur_privateKeyReadEnable = cmpxchg_ret;
            }
        }
    }
    return BAD_FUNC_ARG;
}

#else /* !WOLFSSL_LINUXKM */

int wolfCrypt_SetPrivateKeyReadEnable_fips(int enable, enum wc_KeyType keyType)
{
    if (keyType == WC_KEYTYPE_ALL) {
        int value = GetTLS(&privateKeyReadEnable);
        if (enable == 0) {
            if (value > 0)
                value--;
        }
        else {
            if (value < INT_MAX)
                value++;
        }
        SetTLS(&privateKeyReadEnable, value);
        return 0;
    }
    return BAD_FUNC_ARG;
}

#endif /* !WOLFSSL_LINUXKM */

int wolfCrypt_GetPrivateKeyReadEnable_fips(enum wc_KeyType keyType)
{
    if (keyType == WC_KEYTYPE_ALL) {
        return GetTLS(&privateKeyReadEnable);
    }
    return BAD_FUNC_ARG;
}


/* Trigger an integrity test. */
int wolfCrypt_IntegrityTest_fips(void)
{
    DoSelfTest();
    return 0;
}


/* get current error status, 0 on ok */
int wolfCrypt_GetStatus_fips(void)
{
    if (posStatus != POS_SUCCESS)
        return posReturn;

#ifndef NO_RNG
    if (CheckConTestStatus() != 0)
        return DRBG_CONT_FIPS_E;
#endif

    return 0;
}


/* get current inCore hash */
const char* wolfCrypt_GetCoreHash_fips(void)
{
    return base16_hash;
}


const char* wolfCrypt_GetVersion_fips(void)
{
    return "wolfCrypt v5.2.1";
}


int wc_GetCastStatus_fips(int type)
{
    if (type >= FIPS_CAST_COUNT || type < 0)
        return -1;
    else
        return fipsCastStatus_get(type);
}


int wc_RunCast_fips(int type)
{
    int castErr = 0;
#ifdef WOLFSSL_LINUXKM
    castErr =  DoCAST(type);
#else /* !WOLFSSL_LINUXKM */
    SetTLS(&thisThreadInPOS, 1);
    castErr = DoCAST(type);
    SetTLS(&thisThreadInPOS, 0);
#endif /* !WOLFSSL_LINUXKM */
    if ((castErr != 0) && (fipsMode != FIPS_MODE_DEGRADED)) {
        EnterDegradedMode(castErr);
    }
    return castErr;
}

int wc_RunAllCast_fips(void)
{
    int failCount = 0;

#ifndef WOLFSSL_LINUXKM
    SetTLS(&thisThreadInPOS, 1);
#endif
#if !defined(NO_AES) && !defined(NO_AES_CBC)
#if defined(DEBUG_FIPS_VERBOSE)
    printf("FIPS_CAST_STATE_FAILURE = %d\n", FIPS_CAST_STATE_FAILURE);
    printf("wc_GetCastStatus_fips(FIPS_CAST_AES_CBC) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_AES_CBC));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_AES_CBC) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_AES_CBC) != 0) {
            FIPS_MSG("AES-CBC CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifdef HAVE_AESGCM
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_AES_GCM) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_AES_GCM));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_AES_GCM) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_AES_GCM) != 0) {
            FIPS_MSG("AES-GCM CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifndef NO_SHA
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA1) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA1));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA1) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA1) != 0) {
            FIPS_MSG("HMAC-SHA1 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
    /* the only non-optional CAST */
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_256) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_256));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_256)
                              != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA2_256) != 0) {
            FIPS_MSG("HMAC-SHA2-256 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#ifdef WOLFSSL_SHA512
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_512) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_512));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA2_512)
                              != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA2_512) != 0) {
            FIPS_MSG("HMAC-SHA2-512 CAST failed");
        }
    } else {
        failCount++;
    }
#endif
#ifdef WOLFSSL_SHA3
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA3_256) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA3_256));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_HMAC_SHA3_256)
                              != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_HMAC_SHA3_256) != 0) {
            FIPS_MSG("HMAC-SHA3-256 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifdef HAVE_HASHDRBG
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_DRBG) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_DRBG));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_DRBG) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_DRBG) != 0) {
            FIPS_MSG("Hash_DRBG CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifndef NO_RSA
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_RSA_SIGN_PKCS1v15) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_RSA_SIGN_PKCS1v15));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_RSA_SIGN_PKCS1v15)
                              != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0) {
            FIPS_MSG("RSA sign CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#if defined(HAVE_ECC_CDH) && defined(HAVE_ECC_CDH_CAST)
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_ECC_CDH) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_ECC_CDH));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_ECC_CDH) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_ECC_CDH) != 0) {
            FIPS_MSG("RSA sign CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifdef HAVE_ECC_DHE
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_ECC_PRIMITIVE_Z) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_ECC_PRIMITIVE_Z));
#endif
    /* ECC_PRIMITIVE_Z depends on AES so don't re-run if AES failed */
    if (wc_GetCastStatus_fips(FIPS_CAST_ECC_PRIMITIVE_Z)
                              != FIPS_CAST_STATE_FAILURE)
{
        if (wc_RunCast_fips(FIPS_CAST_ECC_PRIMITIVE_Z) != 0) {
            FIPS_MSG("ECC Primitive Z CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifdef HAVE_ECC
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_ECDSA) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_ECDSA));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_ECDSA) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_ECDSA) != 0) {
            FIPS_MSG("ECDSA CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifndef NO_DH
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_DH_PRIMITIVE_Z) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_DH_PRIMITIVE_Z));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_DH_PRIMITIVE_Z)
                              != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_DH_PRIMITIVE_Z) != 0) {
            FIPS_MSG("DH Primitive Z CAST failed");
        }
    } else {
        failCount++;
    }
#endif
#ifdef WOLFSSL_HAVE_PRF
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_KDF_TLS12) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_KDF_TLS12));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_KDF_TLS12) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_KDF_TLS12) != 0) {
            FIPS_MSG("KDF TLSv1.2 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#if defined(WOLFSSL_HAVE_PRF) && defined(WOLFSSL_TLS13)
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_KDF_TLS13) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_KDF_TLS13));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_KDF_TLS13) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_KDF_TLS13) != 0) {
            FIPS_MSG("KDF TLSv1.3 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifdef WOLFSSL_WOLFSSH
#if defined(DEBUG_FIPS_VERBOSE)
    printf("wc_GetCastStatus_fips(FIPS_CAST_KDF_SSH) = %d\n", wc_GetCastStatus_fips(FIPS_CAST_KDF_SSH));
#endif
    if (wc_GetCastStatus_fips(FIPS_CAST_KDF_SSH) != FIPS_CAST_STATE_FAILURE) {
        if (wc_RunCast_fips(FIPS_CAST_KDF_SSH) != 0) {
            FIPS_MSG("KDF SSHv2.0 CAST failed");
            failCount++;
        }
    } else {
        failCount++;
    }
#endif
#ifndef WOLFSSL_LINUXKM
    SetTLS(&thisThreadInPOS, 0);
#endif

    if (failCount > 0 && fipsMode != FIPS_MODE_DEGRADED) {
        fipsMode = FIPS_MODE_DEGRADED;
        FIPS_MSG("Module status set to: FIPS_MODE_DEGRADED");
    } else if (fipsMode == FIPS_MODE_DEGRADED) {
        FIPS_MSG("Module status - FIPS_MODE_DEGRADED");
    } else {
        FIPS_MSG("Module status - FIPS_MODE_NORMAL");
    }

    return failCount;
}

/* // NOLINTEND(misc-no-recursion) */

/* Aes wrappers */
/* setkey wrapper */
#ifndef NO_AES
int wc_AesSetKey_fips(Aes* aes, const byte* userKey, word32 keylen,
                   const byte* iv, int dir)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesSetKey(aes, userKey, keylen, iv, dir);
}


/* set iv wrapper */
int wc_AesSetIV_fips(Aes* aes, const byte* iv)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesSetIV(aes, iv);
}

#ifdef HAVE_AES_ECB
/* ecb encrypt wrapper */
int wc_AesEcbEncrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesEcbEncrypt(aes, out, in, sz);
}


/* ecb decrypt wrapper */
int wc_AesEcbDecrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz) {
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesEcbDecrypt(aes, out, in, sz);
}
#endif

#ifdef HAVE_AES_CBC
/* cbc encrypt wrapper */
int wc_AesCbcEncrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCbcEncrypt(aes, out, in, sz);
}


/* cbc decrypt wrapper */
int wc_AesCbcDecrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCbcDecrypt(aes, out, in, sz);
}
#endif

#ifdef WOLFSSL_AES_COUNTER
/* ctr encrypt wrapper */
int wc_AesCtrEncrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCtrEncrypt(aes, out, in, sz);
}

int wc_AesCtrSetKey_fips(Aes* aes, const byte* key, word32 len,
                                         const byte* iv, int dir)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesCtrSetKey(aes, key, len, iv, dir);
}
#endif

#ifdef WOLFSSL_AES_OFB
/* ofb encrypt wrapper */
int wc_AesOfbEncrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesOfbEncrypt(aes, out, in, sz);
}


/* ofb decrypt wrapper */
int wc_AesOfbDecrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_AesOfbDecrypt(aes, out, in, sz);
}
#endif
#endif /* NO_AES */


/* gcm set key wrapper */
#ifdef HAVE_AESGCM
int wc_AesGcmSetKey_fips(Aes* aes, const byte* key, word32 len)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AESGCM_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmSetKey(aes, key, len);
}


/* gcm set external iv wrapper */
int wc_AesGcmSetExtIV_fips(Aes* aes, const byte* iv, word32 ivSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AESGCM_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmSetExtIV(aes, iv, ivSz);
}


/* gcm set internal iv wrapper */
int wc_AesGcmSetIV_fips(Aes* aes, word32 ivSz, const byte* ivFixed,
                     word32 ivFixedSz, WC_RNG* rng)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AESGCM_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmSetIV(aes, ivSz, ivFixed, ivFixedSz, rng);
}


/* gcm encrypt wrapper */
int wc_AesGcmEncrypt_fips(Aes* aes, byte* out, const byte* in, word32 sz,
                       byte* ivOut, word32 ivOutSz,
                       byte* authTag, word32 authTagSz,
                       const byte* authIn, word32 authInSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AESGCM_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmEncrypt_ex(aes, out, in, sz, ivOut, ivOutSz,
                               authTag, authTagSz, authIn, authInSz);
}


/* gcm decrypt wrapper */
int wc_AesGcmDecrypt_fips(Aes* aes, byte* out, const byte* in,
                       word32 sz, const byte* iv, word32 ivSz,
                       const byte* authTag, word32 authTagSz,
                       const byte* authIn, word32 authInSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AESGCM_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_AesGcmDecrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                         authIn, authInSz);
}


/* GMAC convenience wrapper */
int wc_Gmac_fips(const byte* key, word32 keySz, byte* iv, word32 ivSz,
              const byte* authIn, word32 authInSz,
              byte* authTag, word32 authTagSz, WC_RNG* rng)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AESGCM_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_Gmac(key, keySz, iv, ivSz, authIn, authInSz,
                   authTag, authTagSz, rng);
}


/* GMAC verify convenience wrapper */
int wc_GmacVerify_fips(const byte* key, word32 keySz,
                    const byte* iv, word32 ivSz,
                    const byte* authIn, word32 authInSz,
                    const byte* authTag, word32 authTagSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AESGCM_KAT_FIPS_E;

    if (AlgoAllowed(FIPS_CAST_AES_GCM) != 0)
        return AESGCM_KAT_FIPS_E;

    return wc_GmacVerify(key, keySz, iv, ivSz,
                         authIn, authInSz, authTag, authTagSz);
}
#endif /* HAVE_AESGCM */


#if defined(HAVE_AESCCM)
/* ccm set key wrapper */
int wc_AesCcmSetKey_fips(Aes* aes, const byte* key, word32 len)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AESCCM_KAT_FIPS_E;

    return wc_AesCcmSetKey(aes, key, len);
}


/* ccm set nonce wrapper */
int wc_AesCcmSetNonce_fips(Aes* aes, const byte* nonce, word32 nonceSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AESCCM_KAT_FIPS_E;

    return wc_AesCcmSetNonce(aes, nonce, nonceSz);
}


/* ccm encrypt wrapper */
int wc_AesCcmEncrypt_fips(Aes* aes, byte* out, const byte* in,
                       word32 sz, byte* ivOut, word32 ivOutSz,
                       byte* authTag, word32 authTagSz,
                       const byte* authIn, word32 authInSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AESCCM_KAT_FIPS_E;

    return wc_AesCcmEncrypt_ex(aes, out, in, sz, ivOut, ivOutSz,
                               authTag, authTagSz, authIn, authInSz);
}


/* ccm decrypt wrapper */
int wc_AesCcmDecrypt_fips(Aes* aes, byte* out, const byte* in,
                       word32 sz, const byte* iv, word32 ivSz,
                       const byte* authTag, word32 authTagSz,
                       const byte* authIn, word32 authInSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AESCCM_KAT_FIPS_E;

    return wc_AesCcmDecrypt(aes, out, in, sz, iv, ivSz, authTag, authTagSz,
                         authIn, authInSz);
}
#endif /* HAVE_AESCCM */


/* Hash wrappers */
#ifndef NO_SHA
/* Init SHA wrapper */
int wc_InitSha_fips(wc_Sha* sha)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA1) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_InitSha(sha);
}


/* SHA Update wrapper */
int wc_ShaUpdate_fips(wc_Sha* sha, const byte* data, word32 len)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA1) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_ShaUpdate(sha, data, len);
}


/* SHA Final wrapper */
int wc_ShaFinal_fips(wc_Sha* sha, byte* hash)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA1) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_ShaFinal(sha, hash);
}

/* SHA-1 Free wrapper */
void wc_ShaFree_fips(wc_Sha* sha)
{
    wc_ShaFree(sha);
}

#endif /* NO_SHA */


#ifndef NO_SHA256
/* Init SHA256 wrapper */
int wc_InitSha256_fips(wc_Sha256* sha)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_InitSha256(sha);
}


/* SHA256 Update wrapper */
int wc_Sha256Update_fips(wc_Sha256* sha, const byte* data, word32 len)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha256Update(sha, data, len);
}


/* SHA256 Final wrapper */
int wc_Sha256Final_fips(wc_Sha256* sha, byte* hash)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha256Final(sha, hash);
}


/* SHA256 Free wrapper */
void wc_Sha256Free_fips(wc_Sha256* sha)
{
    wc_Sha256Free(sha);
}

#ifdef WOLFSSL_SHA224

/* Init SHA224 wrapper */
int wc_InitSha224_fips(wc_Sha224* sha224)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_InitSha224(sha224);
}


/* SHA224 Update wrapper */
int wc_Sha224Update_fips(wc_Sha224* sha224, const byte* data, word32 len)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha224Update(sha224, data, len);
}


/* SHA224 Final wrapper */
int wc_Sha224Final_fips(wc_Sha224* sha224, byte* hash)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha224Final(sha224, hash);
}

/* SHA224 Free wrapper */
void wc_Sha224Free_fips(wc_Sha224* sha)
{
    wc_Sha224Free(sha);
}
#endif /* WOLFSSL_SHA224 */
#endif /* NO_SHA256 */


#ifdef WOLFSSL_SHA512
/* Init SHA512 wrapper */
int wc_InitSha512_fips(wc_Sha512* sha)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_InitSha512(sha);
}


/* SHA512 Update wrapper */
int wc_Sha512Update_fips(wc_Sha512* sha, const byte* data, word32 len)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha512Update(sha, data, len);
}


/* SHA512 Final wrapper */
int wc_Sha512Final_fips(wc_Sha512* sha, byte* hash)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha512Final(sha, hash);
}

/* SHA512 Free wrapper */
void wc_Sha512Free_fips(wc_Sha512* sha)
{
    wc_Sha512Free(sha);
}
#endif /* WOLFSSL_SHA512 */


/* Init SHA384 wrapper */
#ifdef WOLFSSL_SHA384
int wc_InitSha384_fips(wc_Sha384* sha)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_InitSha384(sha);
}


/* SHA384 Update wrapper */
int wc_Sha384Update_fips(wc_Sha384* sha, const byte* data, word32 len)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha384Update(sha, data, len);
}


/* SHA384 Final wrapper */
int wc_Sha384Final_fips(wc_Sha384* sha, byte* hash)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_512) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_Sha384Final(sha, hash);
}

/* SHA384 Free wrapper */
void wc_Sha384Free_fips(wc_Sha384* sha)
{
    wc_Sha384Free(sha);
}
#endif /* WOLFSSL_SHA384 */


#ifdef WOLFSSL_SHA3
/* Base SHA-3 Functions */
int wc_InitSha3_224_fips(wc_Sha3* sha3, void* heap, int devId)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    (void)heap;
    (void)devId;
    return wc_InitSha3_224(sha3, NULL, -1);
}


int wc_Sha3_224_Update_fips(wc_Sha3* sha3, const byte* data, word32 len)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_224_Update(sha3, data, len);
}


int wc_Sha3_224_Final_fips(wc_Sha3* sha3, byte* hash)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_224_Final(sha3, hash);
}

void wc_Sha3_224_Free_fips(wc_Sha3* sha3)
{
    wc_Sha3_224_Free(sha3);
}


int wc_InitSha3_256_fips(wc_Sha3* sha3, void* heap, int devId)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    (void)heap;
    (void)devId;
    return wc_InitSha3_256(sha3, NULL, -1);
}


int wc_Sha3_256_Update_fips(wc_Sha3* sha3, const byte* data, word32 len)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_256_Update(sha3, data, len);
}


int wc_Sha3_256_Final_fips(wc_Sha3* sha3, byte* hash)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_256_Final(sha3, hash);
}


void wc_Sha3_256_Free_fips(wc_Sha3* sha3)
{
    wc_Sha3_256_Free(sha3);
}


int wc_InitSha3_384_fips(wc_Sha3* sha3, void* heap, int devId)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    (void)heap;
    (void)devId;
    return wc_InitSha3_384(sha3, NULL, -1);
}


int wc_Sha3_384_Update_fips(wc_Sha3* sha3, const byte* data, word32 len)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_384_Update(sha3, data, len);
}


int wc_Sha3_384_Final_fips(wc_Sha3* sha3, byte* hash)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_384_Final(sha3, hash);
}


void wc_Sha3_384_Free_fips(wc_Sha3* sha3)
{
    wc_Sha3_384_Free(sha3);
}

int wc_InitSha3_512_fips(wc_Sha3* sha3, void* heap, int devId)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    (void)heap;
    (void)devId;
    return wc_InitSha3_512(sha3, NULL, -1);
}


int wc_Sha3_512_Update_fips(wc_Sha3* sha3, const byte* data, word32 len)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_512_Update(sha3, data, len);
}


int wc_Sha3_512_Final_fips(wc_Sha3* sha3, byte* hash)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA3_256) != 0)
        return SHA3_KAT_FIPS_E;

    return wc_Sha3_512_Final(sha3, hash);
}

void wc_Sha3_512_Free_fips(wc_Sha3* sha3)
{
    wc_Sha3_512_Free(sha3);
}
#endif /* WOLFSSL_SHA3 */


/* HMAC wrappers */

static WC_INLINE int HmacTypeToTest(int hmacType)
{
    switch (hmacType) {
        case WC_SHA:
            return FIPS_CAST_HMAC_SHA1;
        case WC_SHA224:
        case WC_SHA256:
            return FIPS_CAST_HMAC_SHA2_256;
        case WC_SHA384:
        case WC_SHA512:
            return FIPS_CAST_HMAC_SHA2_512;
        case WC_SHA3_224:
        case WC_SHA3_256:
        case WC_SHA3_384:
        case WC_SHA3_512:
            return FIPS_CAST_HMAC_SHA3_256;
        default:
            return FIPS_CAST_COUNT;
    }
}


/* HMAC SetKey wrapper */
int wc_HmacSetKey_fips(Hmac* hmac, int type, const byte* key, word32 keySz)
{
    int testType = FIPS_CAST_COUNT;

    if (FipsAllowed() != 0) {
        return FIPS_NOT_ALLOWED_E;
    }

    if (hmac != NULL)
        testType = HmacTypeToTest(type);
    if (testType == FIPS_CAST_COUNT)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(testType) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_HmacSetKey(hmac, type, key, keySz);
}


/* HMAC Update wrapper */
int wc_HmacUpdate_fips(Hmac* hmac, const byte* data, word32 len)
{
    int testType = FIPS_CAST_COUNT;

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (hmac != NULL)
        testType = HmacTypeToTest(hmac->macType);
    if (testType == FIPS_CAST_COUNT)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(testType) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_HmacUpdate(hmac, data, len);
}


/* HMAC Final wrapper */
int wc_HmacFinal_fips(Hmac* hmac, byte* hash)
{
    int testType = FIPS_CAST_COUNT;

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (hmac != NULL)
        testType = HmacTypeToTest(hmac->macType);
    if (testType == FIPS_CAST_COUNT)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(testType) != 0)
        return HMAC_KAT_FIPS_E;

    return wc_HmacFinal(hmac, hash);
}

/* HMAC Free wrapper */
void wc_HmacFree_fips(Hmac* hmac)
{
    wc_HmacFree(hmac);
}

#ifdef WOLFSSL_HAVE_PRF

/* PRF */
int wc_PRF_fips(byte* result, word32 resLen,
        const byte* secret, word32 secLen,
        const byte* seed, word32 seedLen,
        int hash_type, void* heap, int devId)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_TLS12) != 0)
        return KDF_TLS12_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_PRF(result, resLen, secret, secLen, seed, seedLen,
                hash_type, heap, devId);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}


/* TLS v1.2 PRF */
int wc_PRF_TLSv12_fips(byte* result, word32 resLen,
        const byte* secret, word32 secLen,
        const byte* label, word32 labLen,
        const byte* seed, word32 seedLen,
        int useAtLeastSha256, int hash_type,
        void* heap, int devId)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_TLS12) != 0)
        return KDF_TLS12_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_PRF_TLS(result, resLen, secret, secLen, label, labLen,
                seed, seedLen, useAtLeastSha256, hash_type, heap, devId);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

#endif /* WOLFSSL_HAVE_PRF */


#ifdef HAVE_HKDF

/* HKDF Extract */
int wc_HKDF_Extract_fips(int type,
        const byte* salt, word32 saltSz,
        const byte* inKey, word32 inKeySz, byte* out)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_HKDF_Extract(type, salt, saltSz, inKey, inKeySz, out);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}


/* HKDF Expand */
int wc_HKDF_Expand_fips(int type,
        const byte* inKey, word32 inKeySz,
        const byte* info, word32 infoSz,
        byte* out, word32 outSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_HKDF_Expand(type, inKey, inKeySz, info, infoSz, out, outSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}


/* HKDF */
int wc_HKDF_fips(int type, const byte* inKey, word32 inKeySz,
              const byte* salt, word32 saltSz,
              const byte* info, word32 infoSz,
              byte* out, word32 outSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_HMAC_SHA2_256) != 0)
        return HMAC_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_HKDF(type, inKey, inKeySz, salt, saltSz,
                info, infoSz, out, outSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

int wc_Tls13_HKDF_Extract_fips(byte* prk,
                const byte* salt, int saltLen,
                byte* ikm, int ikmLen, int digest)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_TLS13) != 0)
        return KDF_TLS13_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_Tls13_HKDF_Extract(prk, salt, (word32)saltLen, ikm, (word32)ikmLen, digest);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}


int wc_Tls13_HKDF_Expand_Label_fips(
                byte* okm, word32 okmLen,
                const byte* prk, word32 prkLen,
                const byte* protocol, word32 protocolLen,
                const byte* label, word32 labelLen,
                const byte* info, word32 infoLen,
                int digest)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_TLS13) != 0)
        return KDF_TLS13_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) >0)
        return wc_Tls13_HKDF_Expand_Label(okm, okmLen, prk, prkLen,
                protocol, protocolLen, label, labelLen, info, infoLen, digest);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

#endif /* HAVE_HKDF */


#ifdef WOLFSSL_WOLFSSH

int wc_SSH_KDF_fips(byte hashId, byte keyId,
        byte* key, word32 keySz,
        const byte* k, word32 kSz,
        const byte* h, word32 hSz,
        const byte* sessionId, word32 sessionIdSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_KDF_SSH) != 0)
        return KDF_SSH_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_SSH_KDF(hashId, keyId, key, keySz,
                k, kSz, h, hSz, sessionId, sessionIdSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

#endif /* WOLFSSL_WOLFSSH */


/* RSA wrappers */
#ifndef NO_RSA
/* Init RsaKey */
int wc_InitRsaKey_fips(RsaKey* key, void* p)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_InitRsaKey(key, p);
}


int wc_InitRsaKeyEx_fips(RsaKey* key, void* p, int devId)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_InitRsaKey_ex(key, p, devId);
}


/* Free RsaKey */
int wc_FreeRsaKey_fips(RsaKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_FreeRsaKey(key);
}


/* Check RsaKey */
int wc_CheckRsaKey_fips(RsaKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_CheckRsaKey(key);
}


/* Rsa Public Encrypt */
int wc_RsaPublicEncrypt_fips(const byte* in,word32 inLen,byte* out,
                          word32 outLen, RsaKey* key, WC_RNG* rng)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPublicEncrypt(in, inLen, out, outLen, key, rng);
}


/* Rsa Public Encrypt Extended */
int wc_RsaPublicEncryptEx_fips(const byte* in, word32 inLen, byte* out,
                            word32 outLen, RsaKey* key, WC_RNG* rng, int type,
                            enum wc_HashType hash, int mgf, byte* label,
                            word32 labelSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPublicEncrypt_ex(in, inLen, out, outLen, key, rng, type,
                                  hash, mgf, label, labelSz);
}


/* Rsa Private Decrypt Inline */
int wc_RsaPrivateDecryptInline_fips(byte* in, word32 inLen,
                                 byte** out, RsaKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPrivateDecryptInline(in, inLen, out, key);
}


/* Rsa Private Decrypt Inline Extended */
int wc_RsaPrivateDecryptInlineEx_fips(byte* in, word32 inLen,
                                   byte** out, RsaKey* key, int type,
                                   enum wc_HashType hash, int mgf, byte* label,
                                   word32 labelSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPrivateDecryptInline_ex(in, inLen, out, key, type,
                                         hash, mgf, label, labelSz);
}


/* Rsa Private Decrypt */
int wc_RsaPrivateDecrypt_fips(const byte* in, word32 inLen,
                           byte* out,word32 outLen,RsaKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPrivateDecrypt(in, inLen, out, outLen, key);
}


/* Rsa Private Decrypt Extended */
int wc_RsaPrivateDecryptEx_fips(const byte* in, word32 inLen,
                             byte* out, word32 outLen, RsaKey* key, int type,
                             enum wc_HashType hash, int mgf, byte* label,
                             word32 labelSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPrivateDecrypt_ex(in, inLen, out, outLen, key, type,
                                   hash, mgf, label, labelSz);
}


/* Rsa SSL Sign */
int wc_RsaSSL_Sign_fips(const byte* in, word32 inLen, byte* out,
                     word32 outLen, RsaKey* key, WC_RNG* rng)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaSSL_Sign(in, inLen, out, outLen, key, rng);
}


/* Rsa SSL Verify Inline */
int wc_RsaSSL_VerifyInline_fips(byte* in, word32 inLen, byte** out, RsaKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaSSL_VerifyInline(in, inLen, out, key);
}


/* Rsa SSL Verify */
int wc_RsaSSL_Verify_fips(const byte* in, word32 inLen, byte* out,
                       word32 outLen, RsaKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaSSL_Verify(in, inLen, out, outLen, key);
}


#ifdef WC_RSA_PSS
/* Rsa PSS Sign */
int wc_RsaPSS_Sign_fips(const byte* in, word32 inLen, byte* out, word32 outLen,
                     enum wc_HashType hash, int mgf, RsaKey* key, WC_RNG* rng)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_Sign(in, inLen, out, outLen, hash, mgf, key, rng);
}


/* Rsa PSS Sign Extended */
int wc_RsaPSS_SignEx_fips(const byte* in, word32 inLen,
                       byte* out, word32 outLen,
                       enum wc_HashType hash, int mgf, int saltLen,
                       RsaKey* key, WC_RNG* rng)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_Sign_ex(in, inLen, out, outLen,
                             hash, mgf, saltLen, key, rng);
}


/* Rsa PSS Verify Inline */
int wc_RsaPSS_VerifyInline_fips(byte* in, word32 inLen, byte** out,
                             enum wc_HashType hash, int mgf, RsaKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_VerifyInline(in, inLen, out, hash, mgf, key);
}


/* Rsa PSS Verify Inline Extended */
int wc_RsaPSS_VerifyInlineEx_fips(byte* in, word32 inLen, byte** out,
                               enum wc_HashType hash, int mgf,
                               int saltLen, RsaKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_VerifyInline_ex(in, inLen, out, hash, mgf, saltLen, key);
}


/* Rsa PSS Verify */
int wc_RsaPSS_Verify_fips(byte* in, word32 inLen, byte* out, word32 outLen,
                       enum wc_HashType hash, int mgf, RsaKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_Verify(in, inLen, out, outLen, hash, mgf, key);
}


/* Rsa PSS Verify Extended */
int wc_RsaPSS_VerifyEx_fips(byte* in, word32 inLen, byte* out, word32 outLen,
                               enum wc_HashType hash, int mgf,
                               int saltLen, RsaKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (key == NULL)
        return BAD_FUNC_ARG;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_Verify_ex(in, inLen, out, outLen, hash,
                               mgf, saltLen, key);
}


/* Rsa PSS Check Padding */
int wc_RsaPSS_CheckPadding_fips(const byte* in, word32 inSz,
                             byte* sig, word32 sigSz,
                             enum wc_HashType hashType)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_CheckPadding(in, inSz, sig, sigSz, hashType);
}


/* Rsa PSS Check Padding Extended */
int wc_RsaPSS_CheckPaddingEx_fips(const byte* in, word32 inSz,
                               byte* sig, word32 sigSz,
                               enum wc_HashType hashType,
                               int saltLen, int bits)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPSS_CheckPadding_ex(in, inSz, sig, sigSz, hashType,
                                     saltLen, bits);
}
#endif

/* Rsa Encrypt Size */
int wc_RsaEncryptSize_fips(RsaKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaEncryptSize(key);
}

#if 0
/* Rsa PrivateKey Decode */
int wc_RsaPrivateKeyDecode_fips(const byte* input, word32* inOutIdx,
                             RsaKey* key, word32 inSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPrivateKeyDecode(input, inOutIdx, key, inSz);
}


/* Rsa PublicKey Decode */
int wc_RsaPublicKeyDecode_fips(const byte* input, word32* inOutIdx, RsaKey* key,
                            word32 inSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_RsaPublicKeyDecode(input, inOutIdx, key, inSz);
}
#endif


/* Rsa Export Key */
int wc_RsaExportKey_fips(RsaKey* key,
                      byte* e, word32* eSz, byte* n, word32* nSz,
                      byte* d, word32* dSz, byte* p, word32* pSz,
                      byte* q, word32* qSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_RsaExportKey(key, e, eSz, n, nSz, d, dSz, p, pSz, q, qSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}


#ifdef WOLFSSL_KEY_GEN
#if 0
/* Not meant as a public API, was used for internal testing of some edge cases
 * where libraries could be convinced a non-prime candidate was prime without
 * proper primality testing (M-R)
 */
/* Rsa Check Probable Prime */
int wc_CheckProbablePrime_fips(const byte* p, word32 pSz,
                            const byte* q, word32 qSz,
                            const byte* e, word32 eSz,
                            int nlen, int* isPrime)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_CheckProbablePrime(p, pSz, q, qSz, e, eSz, nlen, isPrime);
}
#endif

/* Rsa Key Gen */
int wc_MakeRsaKey_fips(RsaKey* key, int size, long e, WC_RNG* rng)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_RSA_SIGN_PKCS1v15) != 0)
        return RSA_KAT_FIPS_E;

    return wc_MakeRsaKey(key, size, e, rng);
}
#endif

#endif /* NO_RSA */


/* Base ECC Functions */
#ifdef HAVE_ECC

/* init ECC key */
int wc_ecc_init_fips(ecc_key* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_init(key);
}


/* free ECC key */
int wc_ecc_free_fips(ecc_key* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_free(key);
}


#ifdef ECC_TIMING_RESISTANT
/* set ECC key's RNG */
int wc_ecc_set_rng_fips(ecc_key* key, WC_RNG* rng)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    return wc_ecc_set_rng(key, rng);
}
#endif


/* check ECC key */
int wc_ecc_check_key_fips(ecc_key* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_check_key(key);
}


/* make ECC key */
int wc_ecc_make_key_fips(WC_RNG* rng, int keysize, ecc_key* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_make_key(rng, keysize, key);
}


/* make ECC key extended */
int wc_ecc_make_key_ex_fips(WC_RNG* rng, int keysize, ecc_key* key,
                                     int curve_id)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_make_key_ex(rng, keysize, key, curve_id);
}

#endif /* HAVE_ECC */


#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)

/* ECC Key Export Function */
int wc_ecc_export_x963_fips(ecc_key* key, byte* out, word32* outLen)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    /* When out is NULL, export x963 returns the expected outLen. Allow. */
    if ((key != NULL && out == NULL && outLen != NULL)
            || (GetTLS(&privateKeyReadEnable) > 0))
        return wc_ecc_export_x963(key, out, outLen);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

#endif /* HAVE_ECC && HAVE_ECC_KEY_EXPORT */


#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_IMPORT)

/* ECC Key Import Function */
int wc_ecc_import_x963_fips(const byte* in, word32 inLen, ecc_key* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    return wc_ecc_import_x963(in, inLen, key);
}

#endif /* HAVE_ECC && HAVE_ECC_KEY_EXPORT */


#if defined(HAVE_ECC) && defined(HAVE_ECC_DHE)

/* ECC DHE Function */
int wc_ecc_shared_secret_fips(ecc_key* private_key, ecc_key* public_key,
                                       byte* out, word32* outlen)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECC_PRIMITIVE_Z) != 0)
        return ECDHE_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_ecc_shared_secret(private_key, public_key, out, outlen);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

#endif /* HAVE_ECC && HAVE_ECC_DHE */


#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)

/* ECDSA Signing Function */
int wc_ecc_sign_hash_fips(const byte* in, word32 inlen,
                                   byte* out, word32 *outlen,
                                   WC_RNG* rng, ecc_key* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0) {
        return ECDSA_KAT_FIPS_E;
    }

    return wc_ecc_sign_hash(in, inlen, out, outlen, rng, key);
}

#ifndef WOLFSSL_KCAPI_ECC
int wc_ecc_sign_hash_ex_fips(const byte* in, word32 inlen,
                                   WC_RNG* rng, ecc_key* key, 
                                   MP_INT_T* r, MP_INT_T* s)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;
    
    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0) {
        return ECDSA_KAT_FIPS_E;
    }

    return wc_ecc_sign_hash_ex(in, inlen, rng, key, (mp_int*)r, (mp_int*)s);   
}
#endif
#endif /* HAVE_ECC && HAVE_ECC_SIGN */


/* ECDSA Signature Verify Function */
#if defined(HAVE_ECC) && defined(HAVE_ECC_VERIFY)

int wc_ecc_verify_hash_fips(const byte* sig, word32 siglen,
                                     const byte* hash, word32 hashlen,
                                     int* res, ecc_key* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_verify_hash(sig, siglen, hash, hashlen, res, key);
}

int wc_ecc_verify_hash_ex_fips(MP_INT_T* r, MP_INT_T* s,
                               const byte* hash, word32 hashlen,
                               int* stat, ecc_key* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;
    
    if (AlgoAllowed(FIPS_CAST_ECDSA) != 0)
        return ECDSA_KAT_FIPS_E;

    return wc_ecc_verify_hash_ex((mp_int*)r, (mp_int*)s, hash, hashlen, stat,
                                 key);
}

#endif /* HAVE_ECC && HAVE_ECC_VERIFY */


/* Base DH Functions */
#ifndef NO_DH

/* Init DH key */
int wc_InitDhKey_fips(DhKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_InitDhKey(key);
}


/* Free DH Key */
int wc_FreeDhKey_fips(DhKey* key)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_FreeDhKey(key);
}


/* Set DH Key */
int wc_DhSetKeyEx_fips(DhKey* key, const byte* p, word32 pSz,
                    const byte* g, word32 gSz, const byte* q, word32 qSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhSetKey_ex(key, p, pSz, g, gSz, q, qSz);
}

/* Set trusted domain parameters */
int wc_DhSetNamedKey_fips(DhKey* key, int name)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhSetNamedKey(key, name);
}

/* Generate a DH key pair */
int wc_DhGenerateKeyPair_fips(DhKey* key, WC_RNG* rng,
                           byte* priv, word32* privSz,
                           byte* pub, word32* pubSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_DhGenerateKeyPair(key, rng, priv, privSz, pub, pubSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}


/* Check a DH public key for mathematical correctness */
int wc_DhCheckPubKeyEx_fips(DhKey* key, const byte* pub, word32 pubSz,
                         const byte* prime, word32 primeSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhCheckPubKey_ex(key, pub, pubSz, prime, primeSz);
}


/* Check a DH private key for mathematical correctness */
int wc_DhCheckPrivKeyEx_fips(DhKey* key, const byte* priv, word32 privSz,
                          const byte* prime, word32 primeSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhCheckPrivKey_ex(key, priv, privSz, prime, primeSz);
}


/* Check a DH public and private key for pair-wise consistency */
int wc_DhCheckKeyPair_fips(DhKey* key, const byte* pub, word32 pubSz,
                        const byte* priv, word32 privSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    return wc_DhCheckKeyPair(key, pub, pubSz, priv, privSz);
}


/* Generate shared secret with DH */
int wc_DhAgree_fips(DhKey* key, byte* agree, word32* agreeSz,
                 const byte* priv, word32 privSz, const byte* otherPub,
                 word32 pubSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DH_PRIMITIVE_Z) != 0)
        return DH_KAT_FIPS_E;

    if (GetTLS(&privateKeyReadEnable) > 0)
        return wc_DhAgree(key, agree, agreeSz, priv, privSz, otherPub, pubSz);
    else
        return FIPS_PRIVATE_KEY_LOCKED_E;
}

#endif /* NO_DH */


/* Init RNG */
#ifndef NO_RNG
int wc_InitRng_fips(WC_RNG* rng)
{
    int ret;

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    ret = wc_InitRng(rng);
    if (ret == DRBG_CONT_FIPS_E) {
        SetConTestFailure();
        return DRBG_CONT_FIPS_E;
    }

    return ret;
}


/* Init RNG with Nonce */
int wc_InitRngNonce_fips(WC_RNG* rng, byte* nonce, word32 nonceSz)
{
    int ret;

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    ret = wc_InitRngNonce(rng, nonce, nonceSz);
    if (ret == DRBG_CONT_FIPS_E) {
        SetConTestFailure();
        return DRBG_CONT_FIPS_E;
    }

    return ret;
}


/* Free RNG */
int wc_FreeRng_fips(WC_RNG* rng)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    return wc_FreeRng(rng);
}


#ifdef WC_RNG_SEED_CB
/* Set the seeding callback. */
int wc_SetSeed_Cb_fips(wc_RngSeed_Cb cb)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    return wc_SetSeed_Cb(cb);
}
#endif


/* Generate block of pseudo random numbers */
int wc_RNG_GenerateBlock_fips(WC_RNG* rng, byte* buf, word32 bufSz)
{
    int ret;

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

    ret = wc_RNG_GenerateBlock(rng, buf, bufSz);
    if (ret == DRBG_CONT_FIPS_E) {
        SetConTestFailure();
        return DRBG_CONT_FIPS_E;
    }

    return ret;
}


/* RNG Health Test */
int wc_RNG_HealthTest_fips(int reseed,
                                    const byte* entropyA, word32 entropyASz,
                                    const byte* entropyB, word32 entropyBSz,
                                    byte* output, word32 outputSz)
{
    int ret;

    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_DRBG) != 0)
        return DRBG_KAT_FIPS_E;

#ifdef CUSTOM_RAND_GENERATE_BLOCK
    /* using custom RNG */
    /* consider adding RNG test similar to health test to ensure good entropy */
    ret = 0;
    (void)reseed;
    (void)entropyA;
    (void)entropyASz;
    (void)entropyB;
    (void)entropyBSz;
    (void)output;
    (void)outputSz;
#else
    ret = wc_RNG_HealthTest(reseed, entropyA, entropyASz, entropyB, entropyBSz,
                                                              output, outputSz);
#endif
    if (ret == DRBG_CONT_FIPS_E) {
        SetConTestFailure();
        return DRBG_CONT_FIPS_E;
    }

    return ret;
}

#endif /* NO_RNG */


/* CMAC API */
#ifdef WOLFSSL_CMAC

/* Init CMAC */
int wc_InitCmac_fips(Cmac* cmac, const byte* key, word32 keySz,
                                    int type, void* unused)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_InitCmac(cmac, key, keySz, type, unused);
}


/*  CMAC Update */
int wc_CmacUpdate_fips(Cmac* cmac, const byte* in, word32 inSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_CmacUpdate(cmac, in, inSz);
}


/*  CMAC Final */
int wc_CmacFinal_fips(Cmac* cmac, byte* out, word32* outSz)
{
    if (FipsAllowed() != 0)
        return FIPS_NOT_ALLOWED_E;

    if (AlgoAllowed(FIPS_CAST_AES_CBC) != 0)
        return AES_KAT_FIPS_E;

    return wc_CmacFinal(cmac, out, outSz);
}

#endif /* WOLFSSL_CMAC */


#endif /* HAVE_FIPS */
