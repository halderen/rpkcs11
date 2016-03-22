#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <malloc.h>
#include <pthread.h>

#include "cryptoki_compat/pkcs11.h"
#include "pkcs11.h"
#include "door.h"
#include "doorrpc.h"

static CLIENT *clnt;
static CK_FUNCTION_LIST definition;

int door_call(CLIENT *clnt, char* method, ...);

static void* Unsupported = NULL;

static CK_RV
Initialize(void *args)
{
    CK_RV result;
    door_ARG(result);
    door_call(clnt, "C_Initialize");
    return result;
}

static CK_RV
Finalize(void *args)
{
    CK_RV result;
    door_ARG(result);
    door_call(clnt, "C_Finalize");
    return result;
}

static CK_RV
GetInfo(CK_INFO *info) {
    CK_RV result;
    door_ARG(result);
    door_REF(info);
    door_call(clnt, "C_GetInfo");
    return result;
}

static CK_RV
GetSlotList(unsigned char token_present, CK_SLOT_ID* slot_list, unsigned long *count) {
    CK_RV result;
    door_ARG(result);
    door_ARG(token_present);
    door_ARRAY2(slot_list,count);
    door_call(clnt, "C_GetSlotList");
    return result;
}

static CK_RV
GetSlotInfo(CK_SLOT_ID slot_id, CK_SLOT_INFO* info) {
    CK_RV result;
    door_ARG(result);
    door_ARG(slot_id);
    door_REF(info);
    door_call(clnt, "C_GetSlotInfo");
    return result;
}

static CK_RV
GetTokenInfo(CK_SLOT_ID slot_id, CK_TOKEN_INFO* info) {
    CK_RV result;
    door_ARG(result);
    door_ARG(slot_id);
    door_REF(info);
    door_call(clnt, "C_GetTokenInfo");
    return result;
}

static CK_RV
OpenSession(CK_SLOT_ID slot_id, CK_FLAGS flags, void *application, CK_NOTIFY notify, CK_SESSION_HANDLE *session) {
    CK_RV result;
    (void)application;
    (void)notify;
    door_ARG(result);
    door_ARG(slot_id);
    door_ARG(flags);
    door_REF(session);
    door_call(clnt, "C_OpenSession");
    return result;
}

static CK_RV
CloseSession(CK_SESSION_HANDLE session) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_call(clnt, "C_CloseSession");
    return result;
}

static CK_RV
GetSessionInfo(CK_SESSION_HANDLE session, CK_SESSION_INFO *info) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_REF(info);
    door_call(clnt, "C_GetSessionInfo");
    return result;
}

static CK_RV
Login(CK_SESSION_HANDLE session, CK_USER_TYPE user_type, unsigned char *pin, unsigned long pin_len) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_ARG(user_type);
    door_arg_passstatic(pin,pin_len,sizeof(unsigned char));
    door_call(clnt, "C_Login");
    return result;
}

static CK_RV
Logout(CK_SESSION_HANDLE session) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_call(clnt, "C_Logout");
    return result;
}

static CK_RV
DestroyObject(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_ARG(object);
    door_call(clnt, "C_DestroyObject");
    return result;
}

static CK_RV
GetAttributeValue(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE* templ, unsigned long count) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_ARG(object);
    door_marshall_complexarray(templ, count, sizeof(CK_ATTRIBUTE),
                               offsetof(CK_ATTRIBUTE, pValue), offsetof(CK_ATTRIBUTE, ulValueLen));
    door_call(clnt, "C_GetAttributeValue");
    return result;
}

static CK_RV
FindObjectsInit(CK_SESSION_HANDLE session, CK_ATTRIBUTE *templ, unsigned long count) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_marshall_complexarray(templ, count, sizeof(CK_ATTRIBUTE),
                               offsetof(CK_ATTRIBUTE, pValue), offsetof(CK_ATTRIBUTE, ulValueLen));
    door_call(clnt, "C_FindObjectsInit");
    return result;
}

static CK_RV
FindObjects(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* object, unsigned long max_object_count, unsigned long *object_count) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_ARRAY3(object,max_object_count,object_count);
    door_call(clnt, "C_FindObjects");
    return result;
}

static CK_RV
FindObjectsFinal(CK_SESSION_HANDLE session) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_call(clnt, "C_FindObjectsFinal");
    return result;
}

static CK_RV
DigestInit(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_REF(mechanism);
    door_call(clnt, "C_DigestInit");
    return result;
}

static CK_RV
Digest(CK_SESSION_HANDLE session, unsigned char *data, unsigned long data_len, unsigned char *digest, unsigned long *digest_len) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_ARRAY(data, data_len);
    door_ARRAY2(digest, digest_len);
    door_call(clnt, "C_Digest");
    return result;
}

static CK_RV
SignInit(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism, CK_OBJECT_HANDLE key) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_REF(mechanism);
    door_ARG(key);
    door_call(clnt, "C_SignInit");
    return result;
}

static CK_RV
Sign(CK_SESSION_HANDLE session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_ARRAY(data, data_len);
    door_ARRAY2(signature, signature_len);
    door_call(clnt, "C_Sign");
    return result;
}

static CK_RV
GenerateKey(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism,
            CK_ATTRIBUTE* templ, unsigned long count,
            CK_OBJECT_HANDLE* key)
{
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_REF(mechanism);
    door_marshall_complexarray(templ, count, sizeof(CK_ATTRIBUTE),
                               offsetof(CK_ATTRIBUTE, pValue), offsetof(CK_ATTRIBUTE, ulValueLen));
    door_REF(key);
    door_call(clnt, "C_GenerateKey");
    return result;
}

static CK_RV
GenerateKeyPair(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism, CK_ATTRIBUTE *public_key_template, unsigned long public_key_attribute_count, CK_ATTRIBUTE* private_key_template, unsigned long private_key_attribute_count, CK_OBJECT_HANDLE* public_key, CK_OBJECT_HANDLE* private_key) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_REF(mechanism);
    door_marshall_complexarray(public_key_template, public_key_attribute_count, sizeof(CK_ATTRIBUTE),
                               offsetof(CK_ATTRIBUTE, pValue), offsetof(CK_ATTRIBUTE, ulValueLen));
    door_marshall_complexarray(private_key_template, private_key_attribute_count, sizeof(CK_ATTRIBUTE),
                               offsetof(CK_ATTRIBUTE, pValue), offsetof(CK_ATTRIBUTE, ulValueLen));
    door_REF(public_key);
    door_REF(private_key);
    door_call(clnt, "C_GenerateKeyPair");
    return result;
}

static CK_RV
SeedRandom(CK_SESSION_HANDLE session, unsigned char *seed, unsigned long seed_len) {
    CK_RV result;
    door_call(clnt, "C_SeedRandom",door_ARG(result),door_ARG(session),door_ARRAY(seed,seed_len));
    return result;
}

static CK_RV
GenerateRandom(CK_SESSION_HANDLE session, unsigned char *random_data, unsigned long random_len) {
    CK_RV result;
    door_ARG(result);
    door_ARG(session);
    door_ARRAY(random_data, random_len);
    door_call(clnt, "C_GenerateRandom");
    return result;
}

static CK_RV
GetFunctionList(CK_FUNCTION_LIST_PTR_PTR function_list)
{
  definition.version.major = CRYPTOKI_VERSION_MAJOR;
  definition.version.minor = CRYPTOKI_VERSION_MINOR;
  definition.C_Initialize          = Initialize;
  definition.C_Finalize            = Finalize;
  definition.C_GetInfo             = GetInfo;
  definition.C_GetFunctionList     = GetFunctionList;
  definition.C_GetSlotList         = GetSlotList;
  definition.C_GetSlotInfo         = GetSlotInfo;
  definition.C_GetTokenInfo        = GetTokenInfo;
  definition.C_GetMechanismList    = Unsupported;
  definition.C_GetMechanismInfo    = Unsupported;
  definition.C_InitToken           = Unsupported;
  definition.C_InitPIN             = Unsupported;
  definition.C_SetPIN              = Unsupported;
  definition.C_OpenSession         = OpenSession;
  definition.C_CloseSession        = CloseSession;
  definition.C_CloseAllSessions    = Unsupported;
  definition.C_GetSessionInfo      = GetSessionInfo;
  definition.C_GetOperationState   = Unsupported;
  definition.C_SetOperationState   = Unsupported;
  definition.C_Login               = Login;
  definition.C_Logout              = Logout;
  definition.C_CreateObject        = Unsupported;
  definition.C_CopyObject          = Unsupported;
  definition.C_DestroyObject       = DestroyObject;
  definition.C_GetObjectSize       = Unsupported;
  definition.C_GetAttributeValue   = GetAttributeValue;
  definition.C_SetAttributeValue   = Unsupported;
  definition.C_FindObjectsInit     = FindObjectsInit;
  definition.C_FindObjects         = FindObjects;
  definition.C_FindObjectsFinal    = FindObjectsFinal;
  definition.C_EncryptInit         = Unsupported;
  definition.C_Encrypt             = Unsupported;
  definition.C_EncryptUpdate       = Unsupported;
  definition.C_EncryptFinal        = Unsupported;
  definition.C_DecryptInit         = Unsupported;
  definition.C_Decrypt             = Unsupported;
  definition.C_DecryptUpdate       = Unsupported;
  definition.C_DecryptFinal        = Unsupported;
  definition.C_DigestInit          = DigestInit;
  definition.C_Digest              = Digest;
  definition.C_DigestUpdate        = Unsupported;
  definition.C_DigestKey           = Unsupported;
  definition.C_DigestFinal         = Unsupported;
  definition.C_SignInit            = SignInit;
  definition.C_Sign                = Sign;
  definition.C_SignUpdate          = Unsupported;
  definition.C_SignFinal           = Unsupported;
  definition.C_SignRecoverInit     = Unsupported;
  definition.C_SignRecover         = Unsupported;
  definition.C_VerifyInit          = Unsupported;
  definition.C_Verify              = Unsupported;
  definition.C_VerifyUpdate        = Unsupported;
  definition.C_VerifyFinal         = Unsupported;
  definition.C_VerifyRecoverInit   = Unsupported;
  definition.C_VerifyRecover       = Unsupported;
  definition.C_DigestEncryptUpdate = Unsupported;
  definition.C_DecryptDigestUpdate = Unsupported;
  definition.C_SignEncryptUpdate   = Unsupported;
  definition.C_DecryptVerifyUpdate = Unsupported;
  definition.C_GenerateKey         = GenerateKey;
  definition.C_GenerateKeyPair     = GenerateKeyPair;
  definition.C_WrapKey             = Unsupported;
  definition.C_UnwrapKey           = Unsupported;
  definition.C_DeriveKey           = Unsupported;
  definition.C_SeedRandom          = SeedRandom;
  definition.C_GenerateRandom      = GenerateRandom;
  definition.C_GetFunctionStatus   = Unsupported;
  definition.C_CancelFunction      = Unsupported;
  definition.C_WaitForSlotEvent    = Unsupported;
  *function_list = &definition;
  return 0;
}

CK_RV
C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR function_list)
{
    return GetFunctionList(function_list);
}

int
door_call(CLIENT *clnt, char* method, ...)
{
    enum clnt_stat retval;
    arguments input;
    arguments output;
    door_getcallbuffer(&input.arguments_val,&input.arguments_len);
    output.arguments_len = input.arguments_len;
    output.arguments_val = NULL;
    retval = doorrpcproc_call_1(method, input, &output, clnt);
    door_arg_passback((void*)output.arguments_val);
    if (retval != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return -1;
    } else
        return 0;
}

__attribute__((constructor))
void
init(void)
{
	enum clnt_stat retval;
	void *result;
#ifndef	DEBUG
	clnt = clnt_create ("localhost", DOORRPCPROG, DOORRPCVERS, "udp");
	if (clnt == NULL) {
		clnt_pcreateerror ("localhost");
		exit (1);
	}
#endif
	retval = doorrpcproc_null_1(&result, clnt);
	if (retval != RPC_SUCCESS) {
		clnt_perror (clnt, "call failed");
	}
        door_initialize();
}

__attribute__((destructor))
void
fini(void)
{
#ifndef	DEBUG
	clnt_destroy(clnt);
#endif	 /* DEBUG */
}
