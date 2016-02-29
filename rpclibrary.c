#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <malloc.h>
#include <pthread.h>

#include "cryptoki_compat/pkcs11.h"
#include "pkcs11.h"

static CLIENT *clnt;
static CK_FUNCTION_LIST definition;

static ck_rv_t
Initialize(void *args)
{
    enum clnt_stat retval;
    ck_rv_t result;
    reserved future;
    future.reserved_len = 0;
    future.reserved_val = args;
    retval = pkcsproc_initialize_1(future, &result, clnt);
    if (retval != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else
        return result;
}

static ck_rv_t
Finalize(void *args)
{
    enum clnt_stat retval;
    ck_rv_t result;
    reserved future;
    future.reserved_len = 0;
    future.reserved_val = args;
    retval = pkcsproc_finalize_1(future, &result, clnt);
    if (retval != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else
        return result;
}

static ck_rv_t
GetInfo(CK_INFO *info)
{
    enum clnt_stat retval;
    struct ck_info result;
    if ((retval = pkcsproc_getinfo_1(&result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        memcpy(info, &result, sizeof(*info));
        return result.result;
    }
}

static ck_rv_t
GetSlotList(unsigned char token_present, CK_SLOT_ID *slot_list, unsigned long *count)
{
    enum clnt_stat retval;
    struct slotlist result;
    if ((retval = pkcsproc_getslotlist_1(token_present, &result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        if(slot_list) {
            if(*count < result.slots.slots_len) {
                memcpy(slot_list, result.slots.slots_val, sizeof(ck_slot_id_t)*(*count));
                *count = result.slots.slots_len;
                return CKR_BUFFER_TOO_SMALL;
            } else {
                *count = result.slots.slots_len;
                memcpy(slot_list, result.slots.slots_val, sizeof(ck_slot_id_t)*(*count));
                return result.result;
            }
        } else {
            *count = result.slots.slots_len;
        }
        return result.result;
    }
}

static ck_rv_t
GetSlotInfo(CK_SLOT_ID slot_id, struct ck_slot_info *info)
{
    enum clnt_stat retval;
    struct slotinfo result;
    if ((retval = pkcsproc_getslotinfo_1(slot_id, &result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        memcpy(info, &result, sizeof(*info));
        return result.result;
    }
}

static ck_rv_t
GetTokenInfo(CK_SLOT_ID slot_id, struct ck_token_info *info)
{
    enum clnt_stat retval;
    struct tokeninfo result;
    if ((retval = pkcsproc_gettokeninfo_1(slot_id, &result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        memcpy(info, &result, sizeof(*info));
        return result.result;
    }
}

static ck_rv_t
WaitForSlotEvent(ck_flags_t flags, CK_SLOT_ID *slot, void *args)
{
    enum clnt_stat retval;
    struct slotevent result;
    reserved future;
    future.reserved_len = 0;
    future.reserved_val = args;
    if ((retval = pkcsproc_waitforslotevent_1(flags, future, &result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        *slot = result.slot;
        return result.result;
    }
}

static ck_rv_t
GetMechanismList(ck_slot_id_t slot_id, ck_mechanism_type_t *mechanism_list, unsigned long *count)
{
    enum clnt_stat retval;
    struct mechlist result;
    if ((retval = pkcsproc_getmechanismlist_1(slot_id, &result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        if(mechanism_list) {
            if(*count < result.mechs.mechs_len) {
                memcpy(mechanism_list, result.mechs.mechs_val, sizeof(ck_slot_id_t)*(*count));
                *count = result.mechs.mechs_len;
                return CKR_BUFFER_TOO_SMALL;
            } else {
                *count = result.mechs.mechs_len;
                memcpy(mechanism_list, result.mechs.mechs_val, sizeof(ck_slot_id_t)*(*count));
                return result.result;
            }
        } else {
            *count = result.mechs.mechs_len;
        }
        return result.result;
    }
}

static ck_rv_t
GetMechanismInfo(CK_SLOT_ID slot_id, ck_mechanism_type_t type, struct ck_mechanism_info *info)
{
    enum clnt_stat retval;
    struct mechinfo result;
    if ((retval = pkcsproc_getmechanisminfo_1(slot_id, type, &result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        memcpy(info, &result, sizeof(*info));
        return result.result;
    }
}

static ck_rv_t
InitToken(CK_SLOT_ID slot_id, unsigned char *pin, unsigned long pin_len, unsigned char *label)
{
    enum clnt_stat retval;
    ck_rv_t result;
    buffer buffer;
    buffer.buffer_len = pin_len;
    buffer.buffer_val = pin;
    if ((retval = pkcsproc_inittoken_1(slot_id, buffer, label, &result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        return result;
    }
}

static ck_rv_t
InitPIN(CK_SESSION_HANDLE session, unsigned char *pin, unsigned long pin_len)
{
    enum clnt_stat retval;
    ck_rv_t result;
    buffer buffer;
    buffer.buffer_len = pin_len;
    buffer.buffer_val = pin;
    if ((retval = pkcsproc_initpin_1(session, buffer, &result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        return result;
    }
}

static ck_rv_t
SetPIN(CK_SESSION_HANDLE session, unsigned char *old_pin, unsigned long old_len, unsigned char *new_pin, unsigned long new_len)
{
    enum clnt_stat retval;
    ck_rv_t result;
    buffer oldbuffer;
    buffer newbuffer;
    oldbuffer.buffer_len = old_len;
    oldbuffer.buffer_val = old_pin;
    newbuffer.buffer_len = new_len;
    newbuffer.buffer_val = new_pin;
    if ((retval = pkcsproc_setpin_1(session, oldbuffer, newbuffer, &result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        return result;
    }
}

static ck_rv_t
OpenSession(CK_SLOT_ID slot_id, CK_FLAGS flags, void *application, CK_NOTIFY notify, CK_SESSION_HANDLE *session)
{
    enum clnt_stat retval;
    struct sessionresult result;
    if ((retval = pkcsproc_opensession_1(slot_id, flags, &result, clnt)) != RPC_SUCCESS)
    {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        *session = result.session;
        return result.result;
    }
}

static ck_rv_t
CloseSession(CK_SESSION_HANDLE session)
{
    enum clnt_stat retval;
    ck_rv_t result;
    if ((retval = pkcsproc_closesession_1(session, &result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        return result;
    }
}

static ck_rv_t
CloseAllSessions(CK_SLOT_ID slot_id)
{
    enum clnt_stat retval;
    ck_rv_t result;
    if ((retval = pkcsproc_closeallsessions_1(slot_id, &result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        return result;
    }
}

static ck_rv_t
GetSessionInfo(CK_SESSION_HANDLE session, CK_SESSION_INFO *info)
{
    enum clnt_stat retval;
    struct sessioninfo result;
    if ((retval = pkcsproc_getsessioninfo_1(session, &result, clnt)) != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return CKR_DEVICE_ERROR;
    } else {
        memcpy(info, &result, sizeof(*info));
        return result.result;
    }
}

static ck_rv_t
GetOperationState(ck_session_handle_t session, unsigned char *operation_state, unsigned long *operation_state_len) {
}

static ck_rv_t
SetOperationState(ck_session_handle_t session, unsigned char *operation_state, unsigned long operation_state_len, ck_object_handle_t encryption_key, ck_object_handle_t authentiation_key) {
}

static ck_rv_t
Login(ck_session_handle_t session, ck_user_type_t user_type, unsigned char *pin, unsigned long pin_len) {
}

static ck_rv_t
Logout(ck_session_handle_t session) {
}

static ck_rv_t
CreateObject(ck_session_handle_t session, struct ck_attribute *templ, unsigned long count, ck_object_handle_t *object) {
}

static ck_rv_t
CopyObject(ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, unsigned long count, ck_object_handle_t *new_object) {
}

static ck_rv_t
DestroyObject(ck_session_handle_t session, ck_object_handle_t object) {
}

static ck_rv_t
GetObjectSize(ck_session_handle_t session, ck_object_handle_t object, unsigned long *size) {
}

static ck_rv_t
GetAttributeValue(ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, unsigned long count) {
}

static ck_rv_t
SetAttributeValue(ck_session_handle_t session, ck_object_handle_t object, struct ck_attribute *templ, unsigned long count) {
}

static ck_rv_t
FindObjectsInit(ck_session_handle_t session, struct ck_attribute *templ, unsigned long count) {
}

static ck_rv_t
FindObjects(ck_session_handle_t session, ck_object_handle_t *object, unsigned long max_object_count, unsigned long *object_count) {
}
static ck_rv_t
FindObjectsFinal(ck_session_handle_t session) {
}

static ck_rv_t
EncryptInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) {
}

static ck_rv_t
Encrypt(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *encrypted_data, unsigned long *encrypted_data_len) {
}

static ck_rv_t
EncryptUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {
}

static ck_rv_t
EncryptFinal(ck_session_handle_t session, unsigned char *last_encrypted_part, unsigned long *last_encrypted_part_len) {
}

static ck_rv_t
DecryptInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) {
}

static ck_rv_t
Decrypt(ck_session_handle_t session, unsigned char *encrypted_data, unsigned long encrypted_data_len, unsigned char *data, unsigned long *data_len) {
}

static ck_rv_t
DecryptUpdate(ck_session_handle_t session, unsigned char *encrypted_part, unsigned long encrypted_part_len, unsigned char *part, unsigned long *part_len) {
}

static ck_rv_t
DecryptFinal(ck_session_handle_t session, unsigned char *last_part, unsigned long *last_part_len) {
}

static ck_rv_t
DigestInit(ck_session_handle_t session, struct ck_mechanism *mechanism) {
}

static ck_rv_t
Digest(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *digest, unsigned long *digest_len) {
}

static ck_rv_t
DigestUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len) {
}

static ck_rv_t
DigestKey(ck_session_handle_t session, ck_object_handle_t key) {
}

static ck_rv_t
DigestFinal(ck_session_handle_t session, unsigned char *digest, unsigned long *digest_len) {
}

static ck_rv_t
SignInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) {
}

static ck_rv_t
Sign(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len) {
}

static ck_rv_t
SignUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len) {
}

static ck_rv_t
SignFinal(ck_session_handle_t session, unsigned char *signature, unsigned long *signature_len) {
}

static ck_rv_t
SignRecoverInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) {
}

static ck_rv_t
SignRecover(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long *signature_len) {
}

static ck_rv_t
VerifyInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) {
}

static ck_rv_t
Verify(ck_session_handle_t session, unsigned char *data, unsigned long data_len, unsigned char *signature, unsigned long signature_len) {
}

static ck_rv_t
VerifyUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len) {
}

static ck_rv_t
VerifyFinal(ck_session_handle_t session, unsigned char *signature, unsigned long signature_len) {
}

static ck_rv_t
VerifyRecoverInit(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t key) {
}

static ck_rv_t
VerifyRecover(ck_session_handle_t session, unsigned char *signature, unsigned long signature_len, unsigned char *data, unsigned long *data_len) {
}

static ck_rv_t
DigestEncryptUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {
}

static ck_rv_t
DecryptDigestUpdate(ck_session_handle_t session, unsigned char *encrypted_part, unsigned long encrypted_part_len, unsigned char *part, unsigned long *part_len) {
}

static ck_rv_t
SignEncryptUpdate(ck_session_handle_t session, unsigned char *part, unsigned long part_len, unsigned char *encrypted_part, unsigned long *encrypted_part_len) {
}

static ck_rv_t
DecryptVerifyUpdate(ck_session_handle_t session, unsigned char *encrypted_part, unsigned long encrypted_part_len, unsigned char *part, unsigned long *part_len) {
}

static ck_rv_t
GenerateKey(ck_session_handle_t session, struct ck_mechanism *mechanism, struct ck_attribute *templ, unsigned long count, ck_object_handle_t *key) {
}

static ck_rv_t
GenerateKeyPair(ck_session_handle_t session, struct ck_mechanism *mechanism, struct ck_attribute *public_key_template, unsigned long public_key_attribute_count, struct ck_attribute *private_key_template, unsigned long private_key_attribute_count, ck_object_handle_t *public_key, ck_object_handle_t *private_key) {
}

static ck_rv_t
WrapKey(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t wrapping_key, ck_object_handle_t key, unsigned char *wrapped_key, unsigned long *wrapped_key_len) {
}

static ck_rv_t
UnwrapKey(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t unwrapping_key, unsigned char *wrapped_key, unsigned long wrapped_key_len, struct ck_attribute *templ, unsigned long attribute_count, ck_object_handle_t *key) {
}

static ck_rv_t
DeriveKey(ck_session_handle_t session, struct ck_mechanism *mechanism, ck_object_handle_t base_key, struct ck_attribute *templ, unsigned long attribute_count, ck_object_handle_t *key) {
}

static ck_rv_t
SeedRandom(ck_session_handle_t session, unsigned char *seed, unsigned long seed_len) {
}

static ck_rv_t
GenerateRandom(ck_session_handle_t session, unsigned char *random_data, unsigned long random_len) {
}

static ck_rv_t
GetFunctionStatus(ck_session_handle_t session) {
}

static ck_rv_t
CancelFunction(ck_session_handle_t session) {
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

__attribute__((constructor))
void
init(void)
{
    enum clnt_stat retval;
    void *result;
#ifndef	DEBUG
    clnt = clnt_create("localhost", PKCSPROG, PKCSVERS, "udp");
    if (clnt == NULL) {
        clnt_pcreateerror("localhost");
        exit(1);
    }
#endif
    retval = pkcsproc_null_1(&result, clnt);
    if (retval != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
    }
}

__attribute__((destructor))
void
fini(void)
{
#ifndef	DEBUG
    clnt_destroy(clnt);
#endif
}
