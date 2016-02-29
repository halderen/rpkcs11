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

static ck_rv_t
Initialize(void *args)
{
    CK_RV result;
    door_call(clnt, "C_Initialize",door_ARG(result));
    return result;
}

static ck_rv_t
Finalize(void *args)
{
    CK_RV result;
    door_call(clnt, "C_Finalize",door_ARG(result));
    return result;
}

static ck_rv_t
GetInfo(CK_INFO *info) {
    CK_RV result;
    door_call(clnt, "C_GetInfo",door_ARG(result),door_REF(info));
    return result;
}

static ck_rv_t
GetSlotList(unsigned char token_present, CK_SLOT_ID *slot_list, unsigned long *count) {
    CK_RV result;
    door_call(clnt, "C_GetSlotList",door_ARG(result),door_ARRAY2(slot_list,count));
    return result;
}

static ck_rv_t
GetSlotInfo(CK_SLOT_ID slot_id, struct ck_slot_info *info) {
    CK_RV result;
    door_call(clnt, "C_GetSlotInfo",door_ARG(result),door_REF(info));
    return result;
}

static ck_rv_t
GetTokenInfo(CK_SLOT_ID slot_id, struct ck_token_info *info) {
    CK_RV result;
    door_call(clnt, "C_GetTokenInfo",door_ARG(result),door_REF(info));
    return result;
}

static ck_rv_t
WaitForSlotEvent(ck_flags_t flags, CK_SLOT_ID *slot, void *args) {
    CK_RV result;
    door_call(clnt, "C_WaitForSlotEvent",door_ARG(result),door_REF(slot));
    return result;
}

static ck_rv_t
GetMechanismList(ck_slot_id_t slot_id, ck_mechanism_type_t *mechanism_list, unsigned long *count) {
    CK_RV result;
    door_call(clnt, "C_GetMechanismList",door_ARG(result),door_ARRAY2(mechanism_list,count));
    return result;
}

static ck_rv_t
GetMechanismInfo(CK_SLOT_ID slot_id, ck_mechanism_type_t type, struct ck_mechanism_info *info) {
    CK_RV result;
    door_call(clnt, "C_GetMechanismInfo",door_ARG(result),door_ARG(type),door_REF(info));
    return result;
}

static ck_rv_t
InitToken(CK_SLOT_ID slot_id, unsigned char *pin, unsigned long pin_len, unsigned char *label) {
    CK_RV result;
    door_call(clnt, "C_InitToken",door_ARG(result),door_ARRAY(pin,pin_len),door_STRING(label));
    return result;
}

static ck_rv_t
InitPIN(CK_SESSION_HANDLE session, unsigned char *pin, unsigned long pin_len) {
    CK_RV result;
    door_call(clnt, "C_InitPIN",door_ARG(result),door_ARRAY(pin,pin_len));
    return result;
}

static ck_rv_t
SetPIN(CK_SESSION_HANDLE session, unsigned char *old_pin, unsigned long old_len, unsigned char *new_pin, unsigned long new_len) {
    CK_RV result;
    door_call(clnt, "C_SetPIN",door_ARG(result),door_ARRAY(old_pin,old_len),door_ARRAY(new_pin,new_len));
    return result;
}

static ck_rv_t
OpenSession(CK_SLOT_ID slot_id, CK_FLAGS flags, void *application, CK_NOTIFY notify, CK_SESSION_HANDLE *session) {
    CK_RV result;
    door_call(clnt, "C_OpenSession",door_ARG(result),door_ARG(flags),door_REF(session));
    return result;
}

static ck_rv_t
CloseSession(CK_SESSION_HANDLE session) {
    CK_RV result;
    door_call(clnt, "C_CloseSession",door_ARG(result),door_ARG(session));
    return result;
}

static ck_rv_t
CloseAllSessions(CK_SLOT_ID slot_id) {
    CK_RV result;
    door_call(clnt, "C_CloseAllSessions",door_ARG(result),door_ARG(slot_id));
    return result;
}

static ck_rv_t
GetSessionInfo(CK_SESSION_HANDLE session, CK_SESSION_INFO *info) {
    CK_RV result;
    door_call(clnt, "C_GetSessionInfo",door_ARG(result),door_ARG(session),door_REF(info));
    return result;
}

static ck_rv_t
GetOperationState(ck_session_handle_t session, unsigned char *operation_state, unsigned long *operation_state_len) {
    CK_RV result;
    door_call(clnt, "C_GetOperationState",door_ARG(result),door_ARG(session),door_ARRAY2(operation_state,operation_state_len));
    return result;
}

static ck_rv_t
SetOperationState(ck_session_handle_t session, unsigned char *operation_state, unsigned long operation_state_len, ck_object_handle_t encryption_key, ck_object_handle_t authentiation_key) {
    CK_RV result;
    door_call(clnt, "C_SetOperationState",door_ARG(result),door_ARRAY(operation_state,operation_state_len));
    return result;
}

static ck_rv_t
Login(ck_session_handle_t session, ck_user_type_t user_type, unsigned char *pin, unsigned long pin_len) {
    CK_RV result;
    door_call(clnt, "C_Login",door_ARG(result),door_ARG(user_type),door_ARRAY(pin,pin_len));
    return result;
}

static ck_rv_t
Logout(ck_session_handle_t session) {
    CK_RV result;
    door_call(clnt, "C_Logout",door_ARG(result),door_ARG(session));
    return result;
}

static ck_rv_t
CreateObject(ck_session_handle_t session, struct ck_attribute *templ, unsigned long count, ck_object_handle_t *object) {
    CK_RV result;
    door_call(clnt, "C_CreateObject",door_ARG(result),door_REF(templ),door_ARRAY(object,count));
    return result;
}

static ck_rv_t
CopyObject(ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, unsigned long count, ck_object_handle_t *new_object) {
    CK_RV result;
    door_call(clnt, "C_CopyObject",door_ARG(result),door_ARG(object),door_REF(templ),door_ARRAY(new_object,count));
    return result;
}

static ck_rv_t
DestroyObject(ck_session_handle_t session, ck_object_handle_t object) {
    CK_RV result;
    door_call(clnt, "C_DestroyObject",door_ARG(result),door_ARG(object));
    return result;
}

static ck_rv_t
GetObjectSize(ck_session_handle_t session, ck_object_handle_t object, unsigned long *size) {
    CK_RV result;
    door_call(clnt, "C_GetObjectSize",door_ARG(result),door_ARG(object),door_REF(size));
    return result;
}

static ck_rv_t
GetAttributeValue(ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, unsigned long count) {
    CK_RV result;
    door_call(clnt, "C_GetAttributeValue",door_ARG(result),door_ARG(object),door_REF(templ),door_ARG(count));
    return result;
}

static ck_rv_t
SetAttributeValue(ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, unsigned long count) {
    CK_RV result;
    door_call(clnt, "C_SetAttributeValue",door_ARG(result));
    return result;
}

static ck_rv_t
FindObjectsInit(ck_session_handle_t session, struct ck_attribute *templ, unsigned long count) {
    CK_RV result;
    door_call(clnt, "C_FindObjectsInit",door_ARG(result));
    return result;
}

static ck_rv_t
FindObjects(ck_session_handle_t session, ck_object_handle_t *object, unsigned long max_object_count, unsigned long *object_count) {
    CK_RV result;
    door_call(clnt, "C_FindObjects",door_ARG(result));
    return result;
}
static ck_rv_t
FindObjectsFinal(ck_session_handle_t session) {
    CK_RV result;
    door_call(clnt, "C_FindObjectsFinal",door_ARG(result));
    return result;
}

static ck_rv_t
EncryptInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) {
    CK_RV result;
    door_call(clnt, "C_EncryptInit",door_ARG(result));
    return result;
}

static ck_rv_t
Encrypt(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len) {
    CK_RV result;
    door_call(clnt, "C_Encrypt",door_ARG(result));
    return result;
}

static ck_rv_t
EncryptUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {
    CK_RV result;
    door_call(clnt, "C_EncryptUpdate",door_ARG(result));
    return result;
}

static ck_rv_t
EncryptFinal(ck_session_handle_t session, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len) {
    CK_RV result;
    door_call(clnt, "C_EncryptFinal",door_ARG(result));
    return result;
}

static ck_rv_t
DecryptInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) {
    CK_RV result;
    door_call(clnt, "C_DecryptInit",door_ARG(result));
    return result;
}

static ck_rv_t
Decrypt(ck_session_handle_t session, unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len) {
    CK_RV result;
    door_call(clnt, "C_Decrypt",door_ARG(result));
    return result;
}

static ck_rv_t
DecryptUpdate(ck_session_handle_t session, unsigned char *encrypted_part, unsigned long encrypted_part_len, unsigned char *part, unsigned long *part_len) {
    CK_RV result;
    door_call(clnt, "C_DecryptUpdate",door_ARG(result));
    return result;
}

static ck_rv_t
DecryptFinal(ck_session_handle_t session, unsigned char *last_part, unsigned long *last_part_len) {
    CK_RV result;
    door_call(clnt, "C_DecryptFinal",door_ARG(result));
    return result;
}

static ck_rv_t
DigestInit(ck_session_handle_t session, struct ck_mechanism *mechanism) {
    CK_RV result;
    door_call(clnt, "C_DigestInit",door_ARG(result));
    return result;
}

static ck_rv_t
Digest(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *digest, unsigned long *digest_len) {
    CK_RV result;
    door_call(clnt, "C_Digest",door_ARG(result));
    return result;
}

static ck_rv_t
DigestUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len) {
    CK_RV result;
    door_call(clnt, "C_DigestUpdate",door_ARG(result));
    return result;
}

static ck_rv_t
DigestKey(ck_session_handle_t session, ck_object_handle_t key) {
    CK_RV result;
    door_call(clnt, "C_DigestKey",door_ARG(result));
    return result;
}

static ck_rv_t
DigestFinal(ck_session_handle_t session, unsigned char *digest, unsigned long *digest_len) {
    CK_RV result;
    door_call(clnt, "C_DigestFinal",door_ARG(result));
    return result;
}

static ck_rv_t
SignInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) {
    CK_RV result;
    door_call(clnt, "C_SignInit",door_ARG(result));
    return result;
}

static ck_rv_t
Sign(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len) {
    CK_RV result;
    door_call(clnt, "C_Sign",door_ARG(result));
    return result;
}

static ck_rv_t
SignUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len) {
    CK_RV result;
    door_call(clnt, "C_SignUpdate",door_ARG(result));
    return result;
}

static ck_rv_t
SignFinal(ck_session_handle_t session, unsigned char *signature, unsigned long *signature_len) {
    CK_RV result;
    door_call(clnt, "C_SignFinal",door_ARG(result));
    return result;
}

static ck_rv_t
SignRecoverInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) {
    CK_RV result;
    door_call(clnt, "C_SignRecoverInit",door_ARG(result));
    return result;
}

static ck_rv_t
SignRecover(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len) {
    CK_RV result;
    door_call(clnt, "C_SignRecover",door_ARG(result));
    return result;
}

static ck_rv_t
VerifyInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) {
    CK_RV result;
    door_call(clnt, "C_VerifyInit",door_ARG(result));
    return result;
}

static ck_rv_t
Verify(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long signature_len) {
    CK_RV result;
    door_call(clnt, "C_Verify",door_ARG(result));
    return result;
}

static ck_rv_t
VerifyUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len) {
    CK_RV result;
    door_call(clnt, "C_VerifyUpdate",door_ARG(result));
    return result;
}

static ck_rv_t
VerifyFinal(ck_session_handle_t session, unsigned char *signature, unsigned long signature_len) {
    CK_RV result;
    door_call(clnt, "C_VerifyFinal",door_ARG(result));
    return result;
}

static ck_rv_t
VerifyRecoverInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) {
    CK_RV result;
    door_call(clnt, "C_VerifyRecoverInit",door_ARG(result));
    return result;
}

static ck_rv_t
VerifyRecover(ck_session_handle_t session, unsigned char *signature, unsigned long signature_len, unsigned char *data, unsigned long *data_len) {
    CK_RV result;
    door_call(clnt, "C_VerifyRecover",door_ARG(result));
    return result;
}

static ck_rv_t
DigestEncryptUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {
    CK_RV result;
    door_call(clnt, "C_DigestEncryptUpdate",door_ARG(result));
    return result;
}

static ck_rv_t
DecryptDigestUpdate(ck_session_handle_t session, unsigned char *encrypted_part, unsigned long encrypted_part_len, unsigned char *part, unsigned long *part_len) {
    CK_RV result;
    door_call(clnt, "C_DecryptDigestUpdate",door_ARG(result));
    return result;
}

static ck_rv_t
SignEncryptUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {
    CK_RV result;
    door_call(clnt, "C_SignEncryptUpdate",door_ARG(result));
    return result;
}

static ck_rv_t
DecryptVerifyUpdate(ck_session_handle_t session, unsigned char *encrypted_part, unsigned long encrypted_part_len, unsigned char *part, unsigned long *part_len) {
    CK_RV result;
    door_call(clnt, "C_DecryptVerifyUpdate",door_ARG(result));
    return result;
}

static ck_rv_t
GenerateKey(ck_session_handle_t session, struct ck_mechanism *mechanism, struct ck_attribute *templ, unsigned long count, ck_object_handle_t *key) {
    CK_RV result;
    door_call(clnt, "C_GenerateKey",door_ARG(result));
    return result;
}

static ck_rv_t
GenerateKeyPair(ck_session_handle_t session, struct ck_mechanism *mechanism, struct ck_attribute *public_key_template, unsigned long public_key_attribute_count, struct ck_attribute *private_key_template, unsigned long private_key_attribute_count, ck_object_handle_t *public_key, ck_object_handle_t *private_key) {
    CK_RV result;
    door_call(clnt, "C_GenerateKeyPair",door_ARG(result));
    return result;
}

static ck_rv_t
WrapKey(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t wrapping_key, ck_object_handle_t key, unsigned char *wrapped_key, unsigned long *wrapped_key_len) {
    CK_RV result;
    door_call(clnt, "C_WrapKey",door_ARG(result));
    return result;
}

static ck_rv_t
UnwrapKey(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t unwrapping_key, unsigned char *wrapped_key, unsigned long wrapped_key_len, struct ck_attribute *templ, unsigned long attribute_count, ck_object_handle_t *key) {
    CK_RV result;
    door_call(clnt, "C_UnwrapKey",door_ARG(result));
    return result;
}

static ck_rv_t
DeriveKey(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t base_key, struct ck_attribute *templ, unsigned long attribute_count, ck_object_handle_t *key) {
    CK_RV result;
    door_call(clnt, "C_DeriveKey",door_ARG(result));
    return result;
}

static ck_rv_t
SeedRandom(ck_session_handle_t session, unsigned char *seed, unsigned long seed_len) {
    CK_RV result;
    door_call(clnt, "C_SeedRandom",door_ARG(result));
    return result;
}

static ck_rv_t
GenerateRandom(ck_session_handle_t session, unsigned char *random_data, unsigned long random_len) {
    CK_RV result;
    door_call(clnt, "C_GenerateRandom",door_ARG(result));
    return result;
}

static ck_rv_t
GetFunctionStatus(ck_session_handle_t session) {
    CK_RV result;
    door_call(clnt, "C_GetFunctionStatus",door_ARG(result));
    return result;
}

static ck_rv_t
CancelFunction(ck_session_handle_t session) {
    CK_RV result;
    door_call(clnt, "C_CancelFunction",door_ARG(result));
    return result;
}

static ck_rv_t
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
  definition.C_GetMechanismList    = GetMechanismList;
  definition.C_GetMechanismInfo    = GetMechanismInfo;
  definition.C_InitToken           = InitToken;
  definition.C_InitPIN             = InitPIN;
  definition.C_SetPIN              = SetPIN;
  definition.C_OpenSession         = OpenSession;
  definition.C_CloseSession        = CloseSession;
  definition.C_CloseAllSessions    = CloseAllSessions;
  definition.C_GetSessionInfo      = GetSessionInfo;
  definition.C_GetOperationState   = GetOperationState;
  definition.C_SetOperationState   = SetOperationState;
  definition.C_Login               = Login;
  definition.C_Logout              = Logout;
  definition.C_CreateObject        = CreateObject;
  definition.C_CopyObject          = CopyObject;
  definition.C_DestroyObject       = DestroyObject;
  definition.C_GetObjectSize       = GetObjectSize;
  definition.C_GetAttributeValue   = GetAttributeValue;
  definition.C_SetAttributeValue   = SetAttributeValue;
  definition.C_FindObjectsInit     = FindObjectsInit;
  definition.C_FindObjects         = FindObjects;
  definition.C_FindObjectsFinal    = FindObjectsFinal;
  definition.C_EncryptInit         = EncryptInit;
  definition.C_Encrypt             = Encrypt;
  definition.C_EncryptUpdate       = EncryptUpdate;
  definition.C_EncryptFinal        = EncryptFinal;
  definition.C_DecryptInit         = DecryptInit;
  definition.C_Decrypt             = Decrypt;
  definition.C_DecryptUpdate       = DecryptUpdate;
  definition.C_DecryptFinal        = DecryptFinal;
  definition.C_DigestInit          = DigestInit;
  definition.C_Digest              = Digest;
  definition.C_DigestUpdate        = DigestUpdate;
  definition.C_DigestKey           = DigestKey;
  definition.C_DigestFinal         = DigestFinal;
  definition.C_SignInit            = SignInit;
  definition.C_Sign                = Sign;
  definition.C_SignUpdate          = SignUpdate;
  definition.C_SignFinal           = SignFinal;
  definition.C_SignRecoverInit     = SignRecoverInit;
  definition.C_SignRecover         = SignRecover;
  definition.C_VerifyInit          = VerifyInit;
  definition.C_Verify              = Verify;
  definition.C_VerifyUpdate        = VerifyUpdate;
  definition.C_VerifyFinal         = VerifyFinal;
  definition.C_VerifyRecoverInit   = VerifyRecoverInit;
  definition.C_VerifyRecover       = VerifyRecover;
  definition.C_DigestEncryptUpdate = DigestEncryptUpdate;
  definition.C_DecryptDigestUpdate = DecryptDigestUpdate;
  definition.C_SignEncryptUpdate   = SignEncryptUpdate;
  definition.C_DecryptVerifyUpdate = DecryptVerifyUpdate;
  definition.C_GenerateKey         = GenerateKey;
  definition.C_GenerateKeyPair     = GenerateKeyPair;
  definition.C_WrapKey             = WrapKey;
  definition.C_UnwrapKey           = UnwrapKey;
  definition.C_DeriveKey           = DeriveKey;
  definition.C_SeedRandom          = SeedRandom;
  definition.C_GenerateRandom      = GenerateRandom;
  definition.C_GetFunctionStatus   = GetFunctionStatus;
  definition.C_CancelFunction      = CancelFunction;
  definition.C_WaitForSlotEvent    = WaitForSlotEvent;
  *function_list = &definition;
  return 0;
}

ck_rv_t
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
