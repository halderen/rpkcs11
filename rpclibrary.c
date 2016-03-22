#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <malloc.h>
#include <pthread.h>

#include "cryptoki_compat/pkcs11.h"
#include "pkcs11.h"

static CLIENT *clnt;
static CK_FUNCTION_LIST definition;
static void* Unsupported = NULL;

static CK_RV
Initialize(void *args)
{
    enum clnt_stat retval;
    CK_RV result;
    retval = pkcsproc_initialize_1(&result, clnt);
    if (retval == RPC_SUCCESS) {
        return result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
Finalize(void *args)
{
    enum clnt_stat retval;
    CK_RV result;
    retval = pkcsproc_finalize_1(&result, clnt);
    if (retval == RPC_SUCCESS) {
        return result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
GetInfo(CK_INFO *info)
{
    enum clnt_stat retval;
    struct info result;
    if ((retval = pkcsproc_getinfo_1(&result, clnt)) == RPC_SUCCESS) {
        memcpy(info, &result, sizeof(*info));
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
GetSlotList(unsigned char token_present, CK_SLOT_ID *slot_list, unsigned long *count)
{
    enum clnt_stat retval;
    struct slotlist result;
    if ((retval = pkcsproc_getslotlist_1(token_present, *count, &result, clnt)) == RPC_SUCCESS) {
        if(slot_list) {
            if(*count < result.slots.slots_len/sizeof(CK_SLOT_ID))
                result.slots.slots_len = *count * sizeof(CK_SLOT_ID);
            memcpy(slot_list, result.slots.slots_val, sizeof(CK_SLOT_ID)*result.slots.slots_len);
        }
        *count = result.actualcount;
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
GetSlotInfo(CK_SLOT_ID slot_id, CK_SLOT_INFO* info)
{
    enum clnt_stat retval;
    struct slot_info result;
    if ((retval = pkcsproc_getslotinfo_1(slot_id, &result, clnt)) == RPC_SUCCESS) {
        memcpy(info, &result, sizeof(*info));
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
GetTokenInfo(CK_SLOT_ID slot_id, CK_TOKEN_INFO* info)
{
    enum clnt_stat retval;
    struct token_info result;
    if ((retval = pkcsproc_gettokeninfo_1(slot_id, &result, clnt)) == RPC_SUCCESS) {
        memcpy(info, &result, sizeof(*info));
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
}


static CK_RV
OpenSession(CK_SLOT_ID slot_id, CK_FLAGS flags, void *application, CK_NOTIFY notify, CK_SESSION_HANDLE *session)
{
    enum clnt_stat retval;
    struct sessionresult result;
    if ((retval = pkcsproc_opensession_1(slot_id, flags, &result, clnt)) == RPC_SUCCESS) {
        *session = result.session;
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
CloseSession(CK_SESSION_HANDLE session)
{
    enum clnt_stat retval;
    CK_RV result;
    if ((retval = pkcsproc_closesession_1(session, &result, clnt)) == RPC_SUCCESS) {
       return result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
GetSessionInfo(CK_SESSION_HANDLE session, CK_SESSION_INFO *info)
{
    enum clnt_stat retval;
    struct session_info result;
    if ((retval = pkcsproc_getsessioninfo_1(session, &result, clnt)) == RPC_SUCCESS) {
        memcpy(info, &result, sizeof(*info));
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
Login(CK_SESSION_HANDLE session, unsigned long user_type, unsigned char *pin, unsigned long pin_len) {
    enum clnt_stat retval;
    CK_RV result;
    data credentials;
    credentials.data_val = (char*) pin;
    credentials.data_len = pin_len;
    if ((retval = pkcsproc_login_1(session, user_type, credentials, &result, clnt)) == RPC_SUCCESS) {
        if(result == CKR_USER_ALREADY_LOGGED_IN)
            result = CKR_OK;
        return result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
Logout(CK_SESSION_HANDLE session) {
    enum clnt_stat retval;
    CK_RV result;
    if ((retval = pkcsproc_logout_1(session, &result, clnt)) == RPC_SUCCESS) {
        return result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
DestroyObject(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object) {
    enum clnt_stat retval;
    CK_RV result;
    if ((retval = pkcsproc_destroyobject_1(session, object, &result, clnt)) == RPC_SUCCESS) {
        return result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
GetAttributeValue(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE* templ, unsigned long count) {
    enum clnt_stat retval;
    attributesresult result;
    attributes attrs;
    attrs.attr = templ;
    attrs.count = count;
    if ((retval = pkcsproc_getattributevalue_1(session, object, attrs, &result, clnt)) == RPC_SUCCESS) {
        returnattributes(templ, count, attrs);
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
FindObjectsInit(CK_SESSION_HANDLE session, CK_ATTRIBUTE* templ, unsigned long count) {
    enum clnt_stat retval;
    CK_RV result;
    attributes attrs;
    attrs.attr = templ;
    attrs.count = count;
    if ((retval = pkcsproc_findobjectsinit_1(session, attrs, &result, clnt)) == RPC_SUCCESS) {
        return result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
FindObjects(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* object, unsigned long max_object_count, unsigned long *object_count) {
    enum clnt_stat retval;
    objectsresult result;
    if ((retval = pkcsproc_findobjects_1(session, max_object_count, &result, clnt)) == RPC_SUCCESS) {
        *object_count = result.actualcount;
        if(max_object_count > result.actualcount)
            max_object_count = result.actualcount;
        memcpy(object, result.objects.objects_val, sizeof(CK_OBJECT_HANDLE)*max_object_count);
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
FindObjectsFinal(CK_SESSION_HANDLE session) {
    enum clnt_stat retval;
    CK_RV result;
    if ((retval = pkcsproc_findobjectsfinal_1(session, &result, clnt)) == RPC_SUCCESS) {
        return result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
DigestInit(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism_ptr) {
    enum clnt_stat retval;
    CK_RV result;
    mechanism mech;
    mech.mechanism               = mechanism_ptr->mechanism;
    mech.parameter.parameter_len = mechanism_ptr->ulParameterLen;
    mech.parameter.parameter_val = mechanism_ptr->pParameter;
    if ((retval = pkcsproc_digestinit_1(session, mech, &result, clnt)) == RPC_SUCCESS) {
        return result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
Digest(CK_SESSION_HANDLE session, unsigned char *data_ptr, unsigned long data_len, unsigned char *digest, unsigned long *digest_len) {
    enum clnt_stat retval;
    data plain;
    dataresult result;
    size_t length;
    plain.data_len = data_len;
    plain.data_val = (char*) data_ptr;
    if ((retval = pkcsproc_digest_1(session, plain, *digest_len, &result, clnt)) == RPC_SUCCESS) {
        length = *digest_len;
        if(length > result.data.data_len)
            length = result.data.data_len;
        if(digest)
            memcpy(digest, result.data.data_val, length);
        *digest_len = result.actuallen;
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
SignInit(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism_ptr, CK_OBJECT_HANDLE key) {
    enum clnt_stat retval;
    CK_RV result;
    mechanism mech;
    mech.mechanism               = mechanism_ptr->mechanism;
    mech.parameter.parameter_len = mechanism_ptr->ulParameterLen;
    mech.parameter.parameter_val = mechanism_ptr->pParameter;
    if ((retval = pkcsproc_signinit_1(session, mech, key, &result, clnt)) == RPC_SUCCESS) {
        return result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
Sign(CK_SESSION_HANDLE session, unsigned char *data_ptr, unsigned long data_len, unsigned char *signature, unsigned long *signature_len)
{
    enum clnt_stat retval;
    data plain;
    dataresult result;
    size_t length;
    plain.data_len = data_len;
    plain.data_val = (char*) data_ptr;
    if ((retval = pkcsproc_sign_1(session, plain, *signature_len, &result, clnt)) == RPC_SUCCESS) {
        length = *signature_len;
        if(length > result.data.data_len)
            length = result.data.data_len;
        if(signature)
            memcpy(signature, result.data.data_val, length);
        *signature_len = result.actuallen;
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
GenerateKey(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism_ptr,
        CK_ATTRIBUTE* templ, unsigned long count, CK_OBJECT_HANDLE* key)
{
    enum clnt_stat retval;
    data plain;
    keyresult result;
    mechanism mech;
    attributes attrs;
    mech.mechanism               = mechanism_ptr->mechanism;
    mech.parameter.parameter_len = mechanism_ptr->ulParameterLen;
    mech.parameter.parameter_val = mechanism_ptr->pParameter;
    attrs.attr = templ;
    attrs.count = count;
    if ((retval = pkcsproc_generatekey_1(session, mech, attrs, &result, clnt)) == RPC_SUCCESS) {
        *key = result.key;
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
GenerateKeyPair(CK_SESSION_HANDLE session, CK_MECHANISM* mechanism_ptr,
        CK_ATTRIBUTE* public_key_template, unsigned long public_key_attribute_count,
        CK_ATTRIBUTE* private_key_template, unsigned long private_key_attribute_count,
        CK_OBJECT_HANDLE* public_key, CK_OBJECT_HANDLE* private_key)
{
    enum clnt_stat retval;
    data plain;
    keypairresult result;
    mechanism mech;
    attributes public_key_attrs;
    attributes private_key_attrs;
    mech.mechanism               = mechanism_ptr->mechanism;
    mech.parameter.parameter_len = mechanism_ptr->ulParameterLen;
    mech.parameter.parameter_val = mechanism_ptr->pParameter;
    public_key_attrs.attr = public_key_template;
    public_key_attrs.count = public_key_attribute_count;
    private_key_attrs.attr = private_key_template;
    private_key_attrs.count = private_key_attribute_count;
    if ((retval = pkcsproc_generatekeypair_1(session, mech, public_key_attrs, private_key_attrs, &result, clnt)) == RPC_SUCCESS) {
        *public_key = result.public_key;
        *private_key = result.private_key;
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
SeedRandom(CK_SESSION_HANDLE session, unsigned char *seed_ptr, unsigned long seed_len)
{
    enum clnt_stat retval;
    CK_RV result;
    data seed;
    seed.data_val = (char*) seed_ptr;
    seed.data_len = seed_len;
    if ((retval = pkcsproc_seedrandom_1(session, seed, &result, clnt)) == RPC_SUCCESS) {
        return result;
    } else
        return CKR_DEVICE_ERROR;
}

static CK_RV
GenerateRandom(CK_SESSION_HANDLE session, unsigned char *random_data, unsigned long random_len)
{
    enum clnt_stat retval;
    randomresult result;
    result.data.data_len = random_len;
    result.data.data_val = (char*) random_data;
    if ((retval = pkcsproc_generaterandom_1(session, random_len, &result, clnt)) == RPC_SUCCESS) {
        /*if(result.data.data_len < random_len)
            random_len = result.result;
        memcpy(random_data, result.data.data_val, random_len);*/
        return result.result;
    } else
        return CKR_DEVICE_ERROR;
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
