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

CK_FUNCTION_LIST_PTR pkcs11 = NULL;
CK_SESSION_HANDLE session;
unsigned char id[16];
char id_str[33];

int
setup(char* librarypath)
{
    void* handle = NULL;
    CK_C_GetFunctionList getFunctionList;
    CK_RV status;
    unsigned long numslots, maxslots;
    CK_SLOT_ID* slotids = NULL;

    handle = dlopen(librarypath, RTLD_NOW);
    assert(handle);
    getFunctionList = dlsym(handle, "C_GetFunctionList");
    assert(getFunctionList);
    status = getFunctionList(&pkcs11);
    assert(!status);
    status = pkcs11->C_Initialize(NULL);
    assert(!status || status == CKR_CRYPTOKI_ALREADY_INITIALIZED);

    numslots = maxslots = 0;
    do {
        if (maxslots != numslots) {
            maxslots = numslots;
            slotids = realloc(slotids, sizeof (CK_SLOT_ID) * maxslots);
        }
        CHECK2(pkcs11->C_GetSlotList(CK_TRUE, slotids, &numslots), CKR_BUFFER_TOO_SMALL);
    } while (maxslots != numslots);
    assert(numslots > 0);
    status = pkcs11->C_OpenSession(slotids[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    assert(!status);
    CHECK2(pkcs11->C_Login(session, CKU_USER, (unsigned char*) "1234", strlen("1234")), CKR_USER_ALREADY_LOGGED_IN);
    assert(!status);
    return 0;
}

void
teardown(void)
{
    CHECK(pkcs11->C_Logout(session));
    CHECK(pkcs11->C_CloseSession(session));
    CHECK(pkcs11->C_Finalize(NULL));
}

int
producer(int fd)
{
    unsigned char random_data[1024];
    unsigned long random_len = sizeof (random_data);
    unsigned long keysize = 1024;
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

    memset(random_data, 0, random_len);
    CHECK(pkcs11->C_GenerateRandom(session, random_data, random_len));

    memcpy(id, random_data, sizeof(id));
    tohex(id_str, id, sizeof (id));
    CHECK(pkcs11->C_GenerateKeyPair(session, &keyPairMechanism,
            publicKeyTemplate, sizeof (publicKeyTemplate) / sizeof (CK_ATTRIBUTE),
            privateKeyTemplate, sizeof (privateKeyTemplate) / sizeof (CK_ATTRIBUTE),
            &publicKey, &privateKey));
    printf("created key pair %lu %lu\n", publicKey, privateKey);

    write(fd, id, sizeof(id));
    
    return 0;
}

int
consumer(int fd)
{
    int i;
    unsigned long objectcount;
    CK_OBJECT_HANDLE objectlist[10];
    CK_ATTRIBUTE findTemplate[] = {
        { CKA_ID, id, sizeof(id) }
    };

    read(fd, id, sizeof(id));
    tohex(id_str, id, sizeof (id));

    CHECK(pkcs11->C_FindObjectsInit(session, findTemplate, sizeof (findTemplate) / sizeof (CK_ATTRIBUTE)));
    CHECK(pkcs11->C_FindObjects(session, objectlist, sizeof (objectlist) / sizeof (CK_OBJECT_HANDLE), &objectcount));
    if(objectcount > 0) {
        printf("found the just generated key, there are %lu of them\n", objectcount);;
    } else {
        fprintf(stderr,"key that was just generated not found\n");
        exit(1);
    }
    CHECK(pkcs11->C_FindObjectsFinal(session));

    for(i=0; i<objectcount; i++) {
        CHECK(pkcs11->C_DestroyObject(session, objectlist[i]));
        printf("destroyed key %lu\n", objectlist[i]);
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    int fds[2];

    if (argc != 3 || !(!strcmp(argv[2],"fail") || !strcmp(argv[2],"succeed"))) {
        printf("Usage: %s <full-path-to-pkcs11-shared-library> [ fail | succeed ] \n",argv[0]);
        exit(0);
    }

    pipe(fds);

    if (!strcmp(argv[2], "succeed")) {
        setup(argv[1]);
        producer(fds[1]);
        consumer(fds[1]);
        teardown();
        close(fds[1]);
        close(fds[0]);
    }
    if (!strcmp(argv[2], "fail")) {
        if (fork()) {
            close(fds[1]);
            setup(argv[1]);
            consumer(fds[0]);
            teardown();
            close(fds[0]);
        } else {
            close(fds[0]);
            setup(argv[1]);
            producer(fds[1]);
            teardown();
            close(fds[1]);
        }
    }

    exit(0);
}
