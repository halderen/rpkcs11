#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include "cryptoki_compat/pkcs11.h"
#include "pkcs11.h"

#define CHECKSYS(OP) do { int CHECK_status; if((CHECK_status=(OP)) != CKR_OK) { int CHECK_errno = errno; \
  fprintf(stderr,"operation %s on %s:%d failed: %d %s (%d)\n",#OP,__FILE__,__LINE__,CHECK_status,strerror(CHECK_errno),CHECK_errno); abort(); } } while(0)
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

int currentslotid;
int niters = 100;
pthread_barrier_t barrier;
CK_FUNCTION_LIST_PTR pkcs11 = NULL;

void *
testroutine(void *dummy)
{
    CK_SESSION_HANDLE session;
    unsigned char random_data[16];
    unsigned long random_len = sizeof (random_data);
    (void)dummy;
    CHECK(pkcs11->C_OpenSession(currentslotid, CKF_SERIAL_SESSION, NULL, NULL, &session));
    pthread_barrier_wait(&barrier);
    for(int i=0; i<niters; i++) {
        //memset(random_data, 0, random_len);
        CHECK(pkcs11->C_GenerateRandom(session, random_data, random_len));
        //printf("  %02x%02x..%02x%02x\n",random_data[0],random_data[1],random_data[random_len-2],random_data[random_len-1]);
    }
    CHECK(pkcs11->C_CloseSession(session));
    return NULL;
}

int
main(int argc, char *argv[]) {
    void* handle = NULL;
    CK_C_GetFunctionList getFunctionList;
    CK_RV status;
    unsigned long slotidx, numslots, maxslots;
    CK_SLOT_ID* slotids = NULL;
    CK_SESSION_HANDLE session;
    unsigned char random_data[1024];
    unsigned long random_len = sizeof (random_data);

    int nthreads = 2;
    pthread_t* threads;
    
    if (argc > 1) {
        handle = dlopen(argv[1], RTLD_NOW);
        assert(handle);
    }
    getFunctionList = dlsym(handle, "C_GetFunctionList");
    assert(getFunctionList);
    status = getFunctionList(&pkcs11);
    assert(!status);
    CHECK2(pkcs11->C_Initialize(NULL), CKR_CRYPTOKI_ALREADY_INITIALIZED);
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
        if(slotidx) continue;
        CHECK(pkcs11->C_OpenSession(slotids[0], CKF_SERIAL_SESSION, NULL, NULL, &session));
        CHECK2(pkcs11->C_Login(session, CKU_USER, (unsigned char*)"0000", strlen("0000")), CKR_USER_ALREADY_LOGGED_IN);
        //memset(random_data, 0, random_len);
        CHECK(pkcs11->C_GenerateRandom(session, random_data, random_len));
        //printf("  %02x%02x..%02x%02x\n",random_data[0],random_data[1],random_data[random_len-2],random_data[random_len-1]);
        
        currentslotid = slotids[0];
        pthread_barrier_init(&barrier, NULL, nthreads+1);
        threads = malloc(sizeof(pthread_t)*nthreads);
        for(int i=0; i<nthreads; i++) {
            CHECKSYS(pthread_create(&threads[i], NULL, testroutine, NULL));
        }
        pthread_barrier_wait(&barrier);
        for(int i=0; i<nthreads; i++) {
            void* returnvalue;
            CHECKSYS(pthread_join(threads[i], &returnvalue));
        }
        free(threads);
        pthread_barrier_destroy(&barrier);

        CHECK(pkcs11->C_CloseSession(session));
    }

    CHECK(pkcs11->C_Finalize(NULL));
    return 0;
}
