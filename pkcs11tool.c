#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>
#include "cryptoki_compat/pkcs11.h"
#include "pkcs11.h"

#define CHECK(OP) do { CK_RV CHECK_status; if((CHECK_status=(OP)) != CKR_OK) { \
  fprintf(stderr,"operation %s on %s:%d failed: %s (%ld)\n",#OP,__FILE__,__LINE__,err2str(CHECK_status),CHECK_status); abort(); } } while(0)
#define CHECK2(OP,OK) do { CK_RV CHECK_status; CHECK_status=(OP); if(status != CKR_OK && status != OK) { \
  fprintf(stderr,"operation %s on %s:%d failed: %s (%ld)\n",#OP,__FILE__,__LINE__,err2str(CHECK_status),CHECK_status); abort(); } } while(0)

char*
err2str(CK_RV status)
{
    char* msg;
    switch(status) {
        case CKR_OK:
            return "";
        case CKR_CANCEL: msg = "CKR_CANCEL"; break;
        case CKR_HOST_MEMORY: msg = "CKR_HOST_MEMORY"; break;
        case CKR_SLOT_ID_INVALID: msg = "CKR_SLOT_ID_INVALID"; break;
        case CKR_GENERAL_ERROR: msg = "CKR_GENERAL_ERROR"; break;
        case CKR_FUNCTION_FAILED: msg = "CKR_FUNCTION_FAILED"; break;
        case CKR_ARGUMENTS_BAD: msg = "CKR_ARGUMENTS_BAD"; break;
        case CKR_NO_EVENT: msg = "CKR_NO_EVENT"; break;
        case CKR_NEED_TO_CREATE_THREADS: msg = "CKR_NEED_TO_CREATE_THREADS"; break;
        case CKR_CANT_LOCK: msg = "CKR_CANT_LOCK"; break;
        case CKR_ATTRIBUTE_READ_ONLY: msg = "CKR_ATTRIBUTE_READ_ONLY"; break;
        case CKR_ATTRIBUTE_SENSITIVE: msg = "CKR_ATTRIBUTE_SENSITIVE"; break;
        case CKR_ATTRIBUTE_TYPE_INVALID: msg = "CKR_ATTRIBUTE_TYPE_INVALID"; break;
        case CKR_ATTRIBUTE_VALUE_INVALID: msg = "CKR_ATTRIBUTE_VALUE_INVALID"; break;
        case CKR_DATA_INVALID: msg = "CKR_DATA_INVALID"; break;
        case CKR_DATA_LEN_RANGE: msg = "CKR_DATA_LEN_RANGE"; break;
        case CKR_DEVICE_ERROR: msg = "CKR_DEVICE_ERROR"; break;
        case CKR_DEVICE_MEMORY: msg = "CKR_DEVICE_MEMORY"; break;
        case CKR_DEVICE_REMOVED: msg = "CKR_DEVICE_REMOVED"; break;
        case CKR_ENCRYPTED_DATA_INVALID: msg = "CKR_ENCRYPTED_DATA_INVALID"; break;
        case CKR_ENCRYPTED_DATA_LEN_RANGE: msg = "CKR_ENCRYPTED_DATA_LEN_RANGE"; break;
        case CKR_FUNCTION_CANCELED: msg = "CKR_FUNCTION_CANCELED"; break;
        case CKR_FUNCTION_NOT_PARALLEL: msg = "CKR_FUNCTION_NOT_PARALLEL"; break;
        case CKR_FUNCTION_NOT_SUPPORTED: msg = "CKR_FUNCTION_NOT_SUPPORTED"; break;
        case CKR_KEY_HANDLE_INVALID: msg = "CKR_KEY_HANDLE_INVALID"; break;
        case CKR_KEY_SIZE_RANGE: msg = "CKR_KEY_SIZE_RANGE"; break;
        case CKR_KEY_TYPE_INCONSISTENT: msg = "CKR_KEY_TYPE_INCONSISTENT"; break;
        case CKR_KEY_NOT_NEEDED: msg = "CKR_KEY_NOT_NEEDED"; break;
        case CKR_KEY_CHANGED: msg = "CKR_KEY_CHANGED"; break;
        case CKR_KEY_NEEDED: msg = "CKR_KEY_NEEDED"; break;
        case CKR_KEY_INDIGESTIBLE: msg = "CKR_KEY_INDIGESTIBLE"; break;
        case CKR_KEY_FUNCTION_NOT_PERMITTED: msg = "CKR_KEY_FUNCTION_NOT_PERMITTED"; break;
        case CKR_KEY_NOT_WRAPPABLE: msg = "CKR_KEY_NOT_WRAPPABLE"; break;
        case CKR_KEY_UNEXTRACTABLE: msg = "CKR_KEY_UNEXTRACTABLE"; break;
        case CKR_MECHANISM_INVALID: msg = "CKR_MECHANISM_INVALID"; break;
        case CKR_MECHANISM_PARAM_INVALID: msg = "CKR_MECHANISM_PARAM_INVALID"; break;
        case CKR_OBJECT_HANDLE_INVALID: msg = "CKR_OBJECT_HANDLE_INVALID"; break;
        case CKR_OPERATION_ACTIVE: msg = "CKR_OPERATION_ACTIVE"; break;
        case CKR_OPERATION_NOT_INITIALIZED: msg = "CKR_OPERATION_NOT_INITIALIZED"; break;
        case CKR_PIN_INCORRECT: msg = "CKR_PIN_INCORRECT"; break;
        case CKR_PIN_INVALID: msg = "CKR_PIN_INVALID"; break;
        case CKR_PIN_LEN_RANGE: msg = "CKR_PIN_LEN_RANGE"; break;
        case CKR_PIN_EXPIRED: msg = "CKR_PIN_EXPIRED"; break;
        case CKR_PIN_LOCKED: msg = "CKR_PIN_LOCKED"; break;
        case CKR_SESSION_CLOSED: msg = "CKR_SESSION_CLOSED"; break;
        case CKR_SESSION_COUNT: msg = "CKR_SESSION_COUNT"; break;
        case CKR_SESSION_HANDLE_INVALID: msg = "CKR_SESSION_HANDLE_INVALID"; break;
        case CKR_SESSION_PARALLEL_NOT_SUPPORTED: msg = "CKR_SESSION_PARALLEL_NOT_SUPPORTED"; break;
        case CKR_SESSION_READ_ONLY: msg = "CKR_SESSION_READ_ONLY"; break;
        case CKR_SESSION_EXISTS: msg = "CKR_SESSION_EXISTS"; break;
        case CKR_SESSION_READ_ONLY_EXISTS: msg = "CKR_SESSION_READ_ONLY_EXISTS"; break;
        case CKR_SESSION_READ_WRITE_SO_EXISTS: msg = "CKR_SESSION_READ_WRITE_SO_EXISTS"; break;
        case CKR_SIGNATURE_INVALID: msg = "CKR_SIGNATURE_INVALID"; break;
        case CKR_SIGNATURE_LEN_RANGE: msg = "CKR_SIGNATURE_LEN_RANGE"; break;
        case CKR_TEMPLATE_INCOMPLETE: msg = "CKR_TEMPLATE_INCOMPLETE"; break;
        case CKR_TEMPLATE_INCONSISTENT:            msg = "CKR_TEMPLATE_INCONSISTENT"; break;
        case CKR_TOKEN_NOT_PRESENT:                msg = "CKR_TOKEN_NOT_PRESENT"; break;
        case CKR_TOKEN_NOT_RECOGNIZED:             msg = "CKR_TOKEN_NOT_RECOGNIZED"; break;
        case CKR_TOKEN_WRITE_PROTECTED:            msg = "CKR_TOKEN_WRITE_PROTECTED"; break;
        case CKR_UNWRAPPING_KEY_HANDLE_INVALID:    msg = "CKR_UNWRAPPING_KEY_HANDLE_INVALID"; break;
        case CKR_UNWRAPPING_KEY_SIZE_RANGE:        msg = "CKR_UNWRAPPING_KEY_SIZE_RANGE"; break;
        case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: msg = "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"; break;
        case CKR_USER_ALREADY_LOGGED_IN: msg = "CKR_USER_ALREADY_LOGGED_IN"; break;
        case CKR_USER_NOT_LOGGED_IN: msg = "CKR_USER_NOT_LOGGED_IN"; break;
        case CKR_USER_PIN_NOT_INITIALIZED: msg = "CKR_USER_PIN_NOT_INITIALIZED"; break;
        case CKR_USER_TYPE_INVALID: msg = "CKR_USER_TYPE_INVALID"; break;
        case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: msg = "CKR_USER_ANOTHER_ALREADY_LOGGED_IN"; break;
        case CKR_USER_TOO_MANY_TYPES: msg = "CKR_USER_TOO_MANY_TYPES"; break;
        case CKR_WRAPPED_KEY_INVALID: msg = "CKR_WRAPPED_KEY_INVALID"; break;
        case CKR_WRAPPED_KEY_LEN_RANGE: msg = "CKR_WRAPPED_KEY_LEN_RANGE"; break;
        case CKR_WRAPPING_KEY_HANDLE_INVALID: msg = "CKR_WRAPPING_KEY_HANDLE_INVALID"; break;
        case CKR_WRAPPING_KEY_SIZE_RANGE: msg = "CKR_WRAPPING_KEY_SIZE_RANGE"; break;
        case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: msg = "CKR_WRAPPING_KEY_TYPE_INCONSISTENT"; break;
        case CKR_RANDOM_SEED_NOT_SUPPORTED: msg = "CKR_RANDOM_SEED_NOT_SUPPORTED"; break;
        case CKR_RANDOM_NO_RNG: msg = "CKR_RANDOM_NO_RNG"; break;
        case CKR_DOMAIN_PARAMS_INVALID: msg = "CKR_DOMAIN_PARAMS_INVALID"; break;
        case CKR_BUFFER_TOO_SMALL: msg = "CKR_BUFFER_TOO_SMALL"; break;
        case CKR_SAVED_STATE_INVALID: msg = "CKR_SAVED_STATE_INVALID"; break;
        case CKR_INFORMATION_SENSITIVE: msg = "CKR_INFORMATION_SENSITIVE"; break;
        case CKR_STATE_UNSAVEABLE: msg = "CKR_STATE_UNSAVEABLE"; break;
        case CKR_CRYPTOKI_NOT_INITIALIZED: msg = "CKR_CRYPTOKI_NOT_INITIALIZED"; break;
        case CKR_CRYPTOKI_ALREADY_INITIALIZED: msg = "CKR_CRYPTOKI_ALREADY_INITIALIZED"; break;
        case CKR_MUTEX_BAD: msg = "CKR_MUTEX_BAD"; break;
        case CKR_MUTEX_NOT_LOCKED: msg = "CKR_MUTEX_NOT_LOCKED"; break;
        case CKR_FUNCTION_REJECTED: msg = "CKR_FUNCTION_REJECTED"; break;
        case CKR_VENDOR_DEFINED: msg = "CKR_VENDOR_DEFINED"; break;
        default:
            return "unknown";
    }
    return msg;
}

static void
tohex(char *dst, const unsigned char *src, size_t len)
{
    int i;
    for(i=0; i<len; i++) {
        dst[i*2+0] = "0123456789abcdef"[src[i]>>4];
        dst[i*2+1] = "0123456789abcdef"[src[i]&0xf];
    }
    dst[i*2] = '\0';
}

int
main(int argc, char *argv[]) {
    void* handle = NULL;
    CK_C_GetFunctionList getFunctionList;
    CK_FUNCTION_LIST_PTR pkcs11 = NULL;
    CK_INFO info;
    CK_RV status;
    unsigned long slotidx, numslots, maxslots;
    unsigned long objectidx;
    CK_SLOT_ID* slotids = NULL;
    CK_SLOT_INFO slotinfo;
    CK_TOKEN_INFO tokeninfo;
    CK_SESSION_HANDLE session;
    CK_SESSION_INFO sessioninfo;
    unsigned char random_data[1024];
    unsigned long random_len = sizeof (random_data);

    unsigned long keysize = 1024;
    CK_MECHANISM keyMechanism = {
        CKM_DSA_PARAMETER_GEN, NULL_PTR, 0
    };
    CK_ATTRIBUTE keyTemplate[] = {
        { CKA_PRIME_BITS, &keysize, sizeof(keysize) }
    };
    CK_OBJECT_HANDLE key;

    unsigned char id[16];
    char id_str[33];
    CK_OBJECT_HANDLE publicKey, privateKey;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_MECHANISM keyPairMechanism = {
        CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
    };
    CK_BYTE publicExponent[] = { 1, 0, 1 };
    CK_BBOOL ctrue = CK_TRUE;
    CK_BBOOL cfalse = CK_FALSE;
    CK_BBOOL ctoken = CK_TRUE;
    CK_ATTRIBUTE publicKeyTemplate[] = {
        { CKA_LABEL,(CK_UTF8CHAR*) id_str,   strlen(id_str)   },
        { CKA_ID,                  id,       sizeof(id)       },
        { CKA_KEY_TYPE,            &keyType, sizeof(keyType)  },
        { CKA_VERIFY,              &ctrue,   sizeof(ctrue)    },
        { CKA_ENCRYPT,             &cfalse,  sizeof(cfalse)   },
        { CKA_WRAP,                &cfalse,  sizeof(cfalse)   },
        { CKA_TOKEN,               &ctoken,  sizeof(ctoken)   },
        { CKA_MODULUS_BITS,        &keysize, sizeof(keysize)  },
        { CKA_PUBLIC_EXPONENT, &publicExponent, sizeof(publicExponent)}
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
        { CKA_LABEL,(CK_UTF8CHAR *) id_str, strlen (id_str) },
        { CKA_ID,          id,       sizeof(id)             },
        { CKA_KEY_TYPE,    &keyType, sizeof(keyType) },
        { CKA_SIGN,        &ctrue,   sizeof (ctrue) },
        { CKA_DECRYPT,     &cfalse,  sizeof (cfalse) },
        { CKA_UNWRAP,      &cfalse,  sizeof (cfalse) },
        { CKA_SENSITIVE,   &ctrue,   sizeof (ctrue) },
        { CKA_TOKEN,       &ctrue,   sizeof (ctrue)  },
        { CKA_PRIVATE,     &ctrue,   sizeof (ctrue)  },
        { CKA_EXTRACTABLE, &cfalse,  sizeof (cfalse) }
    };
    
    unsigned long objectcount;
    CK_OBJECT_HANDLE objectlist[10];
    CK_ATTRIBUTE findTemplate[] = {
        { CKA_SIGN, &ctrue, sizeof(ctrue) }
    };

    CK_ATTRIBUTE getTemplate[] = {
        { CKA_ID, NULL_PTR, 5 }
    };

    if (argc > 1) {
        handle = dlopen(argv[1], RTLD_NOW);
        assert(handle);
    }
    getFunctionList = dlsym(handle, "C_GetFunctionList");
    assert(getFunctionList);
    status = getFunctionList(&pkcs11);
    assert(!status);
    CHECK2(pkcs11->C_Initialize(NULL), CKR_CRYPTOKI_ALREADY_INITIALIZED);
    status = pkcs11->C_GetInfo(&info);
    assert(!status);
    printf("GetInfo:\n");
    printf("  cryptoki version       : %d.%d\n", info.cryptokiVersion.major, info.cryptokiVersion.minor);
    printf("  manufacturer           : %.*s\n", (int) sizeof (info.manufacturerID), info.manufacturerID);
    printf("  flags                  : 0x%lx\n", info.flags);
    printf("  library description    : %.*s\n", (int) sizeof (info.libraryDescription), info.libraryDescription);
    printf("  library version        : %d.%d\n", info.libraryVersion.major, info.libraryVersion.minor);
    numslots = maxslots = 0;
    do {
        if (maxslots != numslots) {
            maxslots = numslots;
            slotids = realloc(slotids, sizeof (CK_SLOT_ID) * maxslots);
        }
        CHECK2(pkcs11->C_GetSlotList(CK_TRUE, slotids, &numslots), CKR_BUFFER_TOO_SMALL);
    } while (maxslots != numslots);
    printf("number of slots: %lu\n", numslots);
    for (slotidx = 0; slotidx < numslots; slotidx++) {
        pkcs11->C_GetSlotInfo(slotids[slotidx], &slotinfo);
        assert(!status);
        printf("slot %lu\n", slotidx);
        printf("  GetSlotInfo\n");
        printf("    firmware version     : %d.%d\n", slotinfo.firmwareVersion.major, slotinfo.firmwareVersion.minor);
        printf("    hardware version     : %d.%d\n", slotinfo.hardwareVersion.major, slotinfo.hardwareVersion.minor);
        printf("    flags                : 0x%lx\n", slotinfo.flags);
        printf("    manufacturer         : %.*s\n", (int) sizeof (slotinfo.manufacturerID), slotinfo.manufacturerID);
        printf("    slot description     : %.*s\n", (int) sizeof (slotinfo.slotDescription), slotinfo.slotDescription);
        pkcs11->C_GetTokenInfo(slotids[slotidx], &tokeninfo);
        printf("  GetTokenInfo\n");
        printf("    label                : %.*s\n", (int) sizeof (tokeninfo.label), tokeninfo.label);
        printf("    manufacturer         : %.*s\n", (int) sizeof (tokeninfo.manufacturerID), tokeninfo.manufacturerID);
        printf("    model                : %.*s\n", (int) sizeof (tokeninfo.model), tokeninfo.model);
        printf("    serial number        : %.*s\n", (int) sizeof (tokeninfo.serialNumber), tokeninfo.serialNumber);
        printf("    flags                : 0x%lx\n", tokeninfo.flags);
        printf("    max_session_count    : %lu\n", tokeninfo.ulMaxSessionCount);
        printf("    rw_session_count     : %lu\n", tokeninfo.ulRwSessionCount);
        printf("    max_pin_len          : %lu\n", tokeninfo.ulMaxPinLen);
        printf("    min_pin_len          : %lu\n", tokeninfo.ulMinPinLen);
        printf("    total_public_memory  : %lu\n", tokeninfo.ulTotalPublicMemory);
        printf("    free_public_memory   : %lu\n", tokeninfo.ulFreePublicMemory);
        printf("    total_private_memory : %lu\n", tokeninfo.ulTotalPrivateMemory);
        printf("    free_private_memory  : %lu\n", tokeninfo.ulFreePrivateMemory);
        printf("    hardware version     : %d.%d\n", tokeninfo.hardwareVersion.major, tokeninfo.hardwareVersion.minor);
        printf("    firmware version     : %d.%d\n", tokeninfo.firmwareVersion.major, tokeninfo.firmwareVersion.minor);
        printf("    utc time             : %.*s\n", (int) sizeof (tokeninfo.utcTime), tokeninfo.utcTime);
        CHECK(pkcs11->C_OpenSession(slotids[0], CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &session));
        CHECK(pkcs11->C_GetSessionInfo(session, &sessioninfo));
        assert(!status);
        printf("  GetSessionInfo\n");
        printf("    slot                 : %lu\n", sessioninfo.slotID);
        printf("    state                : %lu\n", sessioninfo.state);
        printf("    flags                : 0x%lx\n", sessioninfo.flags);
        printf("    error                : %lu\n", sessioninfo.ulDeviceError);

        printf("logging in\n");
        CHECK2(pkcs11->C_Login(session, CKU_USER, (unsigned char*)"0000", strlen("0000")), CKR_USER_ALREADY_LOGGED_IN);
        assert(!status);

        memset(random_data, 0, random_len);
        CHECK(pkcs11->C_GenerateRandom(session, random_data, random_len));

#ifdef NOTDEFINED /* not supported */
        memcpy(id, random_data, 16);
        tohex(id_str, id, sizeof(id));
        status = pkcs11->C_GenerateKey(session, &keyMechanism, keyTemplate, sizeof(keyTemplate)/sizeof(CK_ATTRIBUTE), &key);
        checkStatus(status);
#endif

        memcpy(id, random_data, 16);
        tohex(id_str, id, sizeof(id));
        CHECK(pkcs11->C_GenerateKeyPair(session, &keyPairMechanism,
                publicKeyTemplate, sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),
                privateKeyTemplate, sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),
                &publicKey, &privateKey));
        printf("created key pair %lu %lu\n",publicKey,privateKey);

        printf("object should be in %p\n", &getTemplate[0].ulValueLen);
        CHECK(pkcs11->C_GetAttributeValue(session, privateKey, getTemplate, sizeof(getTemplate)/sizeof(CK_ATTRIBUTE)));
        printf("object %lu\n", getTemplate[0].ulValueLen);

        CHECK(pkcs11->C_DestroyObject(session, privateKey));
        printf("destroyed private key %lu\n",privateKey);

#ifdef NOTDEFINED
        CHECK(pkcs11->C_FindObjectsInit(session, findTemplate, sizeof(findTemplate)/sizeof(CK_ATTRIBUTE)));
        CHECK(pkcs11->C_FindObjects(session, objectlist, sizeof(objectlist)/sizeof(CK_OBJECT_HANDLE), &objectcount));

        if (objectcount > sizeof (objectlist) / sizeof (CK_OBJECT_HANDLE)) {
            objectcount = sizeof (objectlist) / sizeof (CK_OBJECT_HANDLE);
        }
        for(objectidx=0; objectidx<objectcount; objectidx++) {
            pkcs11->C_GetAttributeValue(session, objectlist[objectidx], getTemplate, sizeof (getTemplate) / sizeof (CK_ATTRIBUTE));
            printf("object %lu %lu\n", objectidx, getTemplate[0].ulValueLen);
        }
#endif
        CHECK(pkcs11->C_Logout(session));

        status = pkcs11->C_CloseSession(session);
        assert(!status);
    }

    status = pkcs11->C_Finalize(NULL);
    assert(!status);
    return 0;
}
