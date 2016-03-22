#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>
#include "cryptoki_compat/pkcs11.h"
#include "doorrpc.h"
#include "door.h"
#include "server.h"
#include "util.h"

bool_t
doorrpcproc_null_1_svc(void *result, struct svc_req *rqstp) {
    return TRUE;
}

bool_t
doorrpcproc_call_1_svc(char* method, arguments input, arguments* output, struct svc_req *rqstp) {
    CK_RV *resultptr;
    door_setcallbuffer((void*) input.arguments_val);
    if (method == NULL || !strcmp(method, "")) {
        output->arguments_len = 0;
        output->arguments_val = NULL;
        return TRUE;
    } else if (!strcmp(method, "C_Initialize")) {
        resultptr = door_OBJ(CK_RV*);
        door_verify();
        *resultptr = local->C_Initialize(NULL);
    } else if (!strcmp(method, "C_Finalize")) {
        resultptr = door_OBJ(CK_RV*);
        door_verify();
        *resultptr = local->C_Finalize(NULL);
    } else if (!strcmp(method, "C_GetInfo")) {
        CK_INFO* info;
        resultptr = door_OBJ(CK_RV*);
        info = door_OBJ(CK_INFO*);
        door_verify();
        *resultptr = local->C_GetInfo(info);
    } else if (!strcmp(method, "C_GetSlotList")) {
        CK_SLOT_ID* slotlist;
        unsigned long* actualcount;
        unsigned long maxcount;
        unsigned char token_present;
        resultptr = door_OBJ(CK_RV*);
        token_present = door_GET(char);
        maxcount = door_GET(unsigned long);
        (void) maxcount;
        actualcount = door_OBJ(unsigned long*);
        slotlist = door_OBJ(CK_SLOT_ID*);
        door_verify();
        *resultptr = local->C_GetSlotList(token_present, slotlist, actualcount);
    } else if (!strcmp(method, "C_GetSlotInfo")) {
        CK_SLOT_ID slot_id;
        CK_SLOT_INFO* info;
        resultptr = door_OBJ(CK_RV*);
        slot_id = door_GET(CK_SLOT_ID);
        info = door_OBJ(CK_SLOT_INFO*);
        door_verify();
        *resultptr = local->C_GetSlotInfo(slot_id, info);
    } else if (!strcmp(method, "C_GetTokenInfo")) {
        CK_SLOT_ID slot_id;
        CK_TOKEN_INFO* info;
        resultptr = door_OBJ(CK_RV*);
        slot_id = door_GET(CK_SLOT_ID);
        info = door_OBJ(CK_TOKEN_INFO*);
        door_verify();
        *resultptr = local->C_GetTokenInfo(slot_id, info);
    } else if (!strcmp(method, "C_OpenSession")) {
        CK_SLOT_ID slot_id;
        CK_FLAGS flags;
        CK_SESSION_HANDLE* session;
        resultptr = door_OBJ(CK_RV*);
        slot_id = door_GET(CK_SLOT_ID);
        flags = door_GET(CK_FLAGS);
        session = door_OBJ(CK_SESSION_HANDLE*);
        door_verify();
        *resultptr = local->C_OpenSession(slot_id, flags, NULL, NULL, session);
    } else if (!strcmp(method, "C_CloseSession")) {
        CK_SESSION_HANDLE session;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        door_verify();
        *resultptr = local->C_CloseSession(session);
    } else if (!strcmp(method, "C_GetSessionInfo")) {
        CK_SESSION_HANDLE session;
        CK_SESSION_INFO* info;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        info = door_OBJ(CK_SESSION_INFO*);
        door_verify();
        *resultptr = local->C_GetSessionInfo(session, info);
    } else if (!strcmp(method, "C_Login")) {
        CK_SESSION_HANDLE session;
        CK_USER_TYPE user_type;
        unsigned char* pin;
        unsigned long pin_len;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        user_type = door_GET(CK_USER_TYPE);
        pin_len = door_GET(unsigned long);
        pin = door_OBJ(unsigned char*);
        door_verify();
        *resultptr = local->C_Login(session, user_type, pin, pin_len);
        if(*resultptr == CKR_USER_ALREADY_LOGGED_IN)
            *resultptr = CKR_OK;
    } else if (!strcmp(method, "C_Logout")) {
        CK_SESSION_HANDLE session;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        door_verify();
        *resultptr = local->C_Logout(session);
    } else if (!strcmp(method, "C_GenerateKey")) {
        CK_SESSION_HANDLE session;
        CK_MECHANISM* mechanism;
        CK_ATTRIBUTE* template;
        CK_OBJECT_HANDLE* key;
        unsigned long count;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        mechanism = door_OBJ(CK_MECHANISM*);
        door_unmarshall_complexarray((void**)&template, &count, sizeof(CK_ATTRIBUTE),
                                     offsetof(CK_ATTRIBUTE, pValue), offsetof(CK_ATTRIBUTE, ulValueLen));
        key = door_OBJ(CK_OBJECT_HANDLE*);
        door_verify();
        *resultptr = local->C_GenerateKey(session, mechanism, template, count, key);
    } else if (!strcmp(method, "C_GenerateKeyPair")) {
        CK_SESSION_HANDLE session;
        CK_MECHANISM* mechanism;
        CK_ATTRIBUTE* public_key_template;
        unsigned long public_key_attribute_count;
        CK_ATTRIBUTE* private_key_template;
        unsigned long private_key_attribute_count;
        CK_OBJECT_HANDLE* public_key;
        CK_OBJECT_HANDLE* private_key;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        mechanism = door_OBJ(CK_MECHANISM*);
        door_unmarshall_complexarray(&public_key_template, &public_key_attribute_count, sizeof(CK_ATTRIBUTE),
                                     offsetof(CK_ATTRIBUTE, pValue), offsetof(CK_ATTRIBUTE, ulValueLen));
        door_unmarshall_complexarray(&private_key_template, &private_key_attribute_count, sizeof(CK_ATTRIBUTE),
                                     offsetof(CK_ATTRIBUTE, pValue), offsetof(CK_ATTRIBUTE, ulValueLen));
        public_key = door_OBJ(CK_OBJECT_HANDLE*);
        private_key = door_OBJ(CK_OBJECT_HANDLE*);
        door_verify();
        *resultptr = local->C_GenerateKeyPair(session, mechanism, public_key_template, public_key_attribute_count,
                                              private_key_template, private_key_attribute_count, public_key, private_key);
    } else if (!strcmp(method, "C_GenerateRandom")) {
        CK_SESSION_HANDLE session;
        unsigned char *random_data;
        unsigned long random_len;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        random_len = door_GET(unsigned long);
        random_data = door_OBJ(unsigned char*);
        door_verify();
        *resultptr = local->C_GenerateRandom(session, random_data, random_len);
    } else if (!strcmp(method, "C_DestroyObject")) {
        CK_SESSION_HANDLE session;
        CK_OBJECT_HANDLE object;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        object = door_GET(CK_OBJECT_HANDLE);
        door_verify();
        *resultptr = local->C_DestroyObject(session, object);
    } else if (!strcmp(method, "C_GetAttributeValue")) {
        CK_SESSION_HANDLE session;
        CK_OBJECT_HANDLE object;
        CK_ATTRIBUTE* template;
        unsigned long count;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        object = door_GET(CK_OBJECT_HANDLE);
        door_unmarshall_complexarray(&template, &count, sizeof (CK_ATTRIBUTE),
                offsetof(CK_ATTRIBUTE, pValue), offsetof(CK_ATTRIBUTE, ulValueLen));
        door_verify();
        *resultptr = local->C_GetAttributeValue(session, object, template, count);
    } else if (!strcmp(method, "C_FindObjectsInit")) {
        CK_SESSION_HANDLE session;
        CK_ATTRIBUTE* template;
        unsigned long count;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        door_unmarshall_complexarray(&template, &count, sizeof (CK_ATTRIBUTE),
                offsetof(CK_ATTRIBUTE, pValue), offsetof(CK_ATTRIBUTE, ulValueLen));
        door_verify();
        *resultptr = local->C_FindObjectsInit(session, template, count);
    } else if (!strcmp(method, "C_FindObjects")) {
        CK_SESSION_HANDLE session;
        CK_OBJECT_HANDLE* objectlist;
        unsigned long* actualcount;
        unsigned long maxcount;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        maxcount = door_GET(unsigned long);
        actualcount = door_OBJ(unsigned long*);
        objectlist = door_OBJ(CK_OBJECT_HANDLE*);
        door_verify();
        *resultptr = local->C_FindObjects(session, objectlist, maxcount, actualcount);
    } else if (!strcmp(method, "C_FindObjectsFinal")) {
        CK_SESSION_HANDLE session;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        door_verify();
        *resultptr = local->C_FindObjectsFinal(session);
    } else if (!strcmp(method, "C_DigestInit")) {
        CK_SESSION_HANDLE session;
        CK_MECHANISM* mechanism;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        mechanism = door_OBJ(CK_MECHANISM*);
        door_verify();
        *resultptr = local->C_DigestInit(session, mechanism);
    } else if (!strcmp(method, "C_Digest")) {
        CK_SESSION_HANDLE session;
        unsigned char* data;
        unsigned long data_len;
        unsigned char* digest;
        unsigned long* digest_len;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        data_len = door_GET(unsigned long);
        data = door_OBJ(unsigned char*);
        (void)door_GET(unsigned long);
        digest_len = door_OBJ(unsigned long*);
        digest = door_OBJ(unsigned char*);
        door_verify();
        *resultptr = local->C_Digest(session, data, data_len, digest, digest_len);
    } else if (!strcmp(method, "C_SignInit")) {
        CK_SESSION_HANDLE session;
        CK_MECHANISM* mechanism;
        CK_OBJECT_HANDLE key;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        mechanism = door_OBJ(CK_MECHANISM*);
        key = door_GET(CK_OBJECT_HANDLE);
        door_verify();
        *resultptr = local->C_SignInit(session, mechanism, key);
    } else if (!strcmp(method, "C_Sign")) {
        CK_SESSION_HANDLE session;
        unsigned char* data;
        unsigned long data_len;
        unsigned char* signature;
        unsigned long* signature_len;
        resultptr = door_OBJ(CK_RV*);
        session = door_GET(CK_SESSION_HANDLE);
        data_len = door_GET(unsigned long);
        data = door_OBJ(unsigned char*);
        (void)door_GET(unsigned long);
        signature_len = door_OBJ(unsigned long*);
        signature = door_OBJ(unsigned char*);
        door_verify();
        *resultptr = local->C_Sign(session, data, data_len, signature, signature_len);
    } else {
        return FALSE;
    }
    output->arguments_len = input.arguments_len;
    output->arguments_val = malloc(input.arguments_len);
    memcpy(output->arguments_val, input.arguments_val, input.arguments_len);
    door_return((void*) output->arguments_val);
    door_setcallbuffer(NULL);
    return TRUE;
}

int
doorrpcprog_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result) {
    xdr_free(xdr_result, result);
    return 1;
}
