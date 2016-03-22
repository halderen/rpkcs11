#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>
#include "pkcs11.h"
#include "cryptoki_compat/pkcs11.h"
#include "server.h"

bool_t
pkcsproc_null_1_svc(void *result, struct svc_req *rqstp) {
    return TRUE;
}

bool_t
pkcsproc_initialize_1_svc(u_long *result, struct svc_req *rqstp)
{
    *result = local->C_Initialize(NULL);
    return TRUE;
}

bool_t
pkcsproc_finalize_1_svc(u_long *result, struct svc_req *rqstp)
{
    *result = local->C_Finalize(NULL);
    return TRUE;

}

bool_t
pkcsproc_getinfo_1_svc(info *result, struct svc_req *rqstp)
{
    result->result = local->C_GetInfo((CK_INFO*)result);
    return TRUE;
}

bool_t
pkcsproc_getslotlist_1_svc(u_char token_present, unsigned long maxcount, slotlist *result, struct svc_req *rqstp)
{
    result->slots.slots_len = sizeof(unsigned long)*maxcount;
    result->slots.slots_val = malloc(result->slots.slots_len);
    result->actualcount = maxcount;
    if(maxcount == 0) {
        result->result = local->C_GetSlotList(token_present, NULL, &result->actualcount);
    } else {
        result->result = local->C_GetSlotList(token_present, (CK_SLOT_ID*)result->slots.slots_val, &result->actualcount);
    }
    return TRUE;
}

bool_t
pkcsproc_getslotinfo_1_svc(u_long slot_id, slot_info *result,  struct svc_req *rqstp)
{
    result->result = local->C_GetSlotInfo(slot_id, (CK_SLOT_INFO*)result);
    return TRUE;
}

bool_t
pkcsproc_gettokeninfo_1_svc(u_long slot_id, token_info *result,  struct svc_req *rqstp)
{
    result->result = local->C_GetTokenInfo(slot_id, (CK_TOKEN_INFO*)result);
    return TRUE;
}

bool_t
pkcsproc_opensession_1_svc(u_long slot_id, u_long flags, sessionresult *result,  struct svc_req *rqstp)
{
    result->result = local->C_OpenSession(slot_id, flags, NULL, NULL, &result->session);
    return TRUE;
}

bool_t
pkcsproc_closesession_1_svc(u_long session, u_long *result,  struct svc_req *rqstp)
{
    *result = local->C_CloseSession(session);
    return TRUE;
}

bool_t
pkcsproc_getsessioninfo_1_svc(u_long session, session_info *result,  struct svc_req *rqstp)
{
    result->result = local->C_GetSessionInfo(session, (CK_SESSION_INFO*)result);
    return TRUE;
}

bool_t
pkcsproc_login_1_svc(u_long session, u_long user_type, data pin, u_long *result,  struct svc_req *rqstp)
{
    *result = local->C_Login(session, user_type, (unsigned char*)pin.data_val, (unsigned long)pin.data_len);
    return TRUE;
}

bool_t
pkcsproc_logout_1_svc(u_long session, u_long *result,  struct svc_req *rqstp)
{
    *result = local->C_Logout(session);
    return TRUE;
}

bool_t
pkcsproc_destroyobject_1_svc(u_long session, u_long object, u_long *result,  struct svc_req *rqstp)
{
    *result = local->C_DestroyObject(session, object);
    return TRUE;
}

bool_t
pkcsproc_getattributevalue_1_svc(u_long session, u_long object, attributes attrs, attributesresult *result,  struct svc_req *rqstp)
{
    result->result = local->C_GetAttributeValue(session, object, attrs.attr, attrs.count);
    result->actualcount = attrs.count;
    duplicateattributes(&result->template, attrs);
    return TRUE;
}

bool_t
pkcsproc_findobjectsinit_1_svc(u_long session, attributes attrs, u_long *result,  struct svc_req *rqstp)
{
    *result = local->C_FindObjectsInit(session, attrs.attr, attrs.count);
    return TRUE;
}

bool_t
pkcsproc_findobjects_1_svc(u_long session, u_long maxcount, objectsresult *result,  struct svc_req *rqstp)
{
    result->objects.objects_len = sizeof(unsigned long) * maxcount;
    result->objects.objects_val = malloc(result->objects.objects_len);
    result->result = local->C_FindObjects(session, result->objects.objects_val, maxcount, &result->actualcount);
    return TRUE;
}

bool_t
pkcsproc_findobjectsfinal_1_svc(u_long session, u_long *result,  struct svc_req *rqstp)
{
    *result = local->C_FindObjectsFinal(session);
    return TRUE;
}

bool_t
pkcsproc_digestinit_1_svc(u_long session, mechanism mech, u_long *result,  struct svc_req *rqstp)
{
    CK_MECHANISM arg;
    arg.mechanism      = mech.mechanism;
    arg.pParameter     = mech.parameter.parameter_val;
    arg.ulParameterLen = mech.parameter.parameter_len;
    *result = local->C_DigestInit(session, &arg);
    return TRUE;
}

bool_t
pkcsproc_digest_1_svc(u_long session, data plain, u_long digest_len, dataresult *result,  struct svc_req *rqstp)
{
    result->data.data_len = digest_len;
    result->data.data_val = malloc(result->data.data_len);
    result->actuallen     = digest_len;
    result->result = local->C_Digest(session, (unsigned char*)plain.data_val, (unsigned long)plain.data_val, (unsigned char*) result->data.data_val, &result->actuallen);
    return TRUE;
}

bool_t
pkcsproc_signinit_1_svc(u_long session, mechanism mech, u_long key, u_long *result,  struct svc_req *rqstp)
{
    CK_MECHANISM arg;
    arg.mechanism      = mech.mechanism;
    arg.pParameter     = mech.parameter.parameter_val;
    arg.ulParameterLen = mech.parameter.parameter_len;
    *result = local->C_SignInit(session, &arg, key);
    return TRUE;
}

bool_t
pkcsproc_sign_1_svc(u_long session, data plain, u_long signature_len, dataresult *result,  struct svc_req *rqstp)
{
    result->data.data_len = signature_len;
    result->data.data_val = malloc(result->data.data_len);
    result->actuallen     = signature_len;
    result->result = local->C_Sign(session, (unsigned char*)plain.data_val, (unsigned long)plain.data_val,
            (unsigned char*)result->data.data_val, &result->actuallen);
    return TRUE;
}

bool_t
pkcsproc_generatekey_1_svc(u_long session, mechanism mech, attributes attrs, keyresult *result,  struct svc_req *rqstp)
{
    CK_MECHANISM arg;
    arg.mechanism      = mech.mechanism;
    arg.pParameter     = mech.parameter.parameter_val;
    arg.ulParameterLen = mech.parameter.parameter_len;
    result->result = local->C_GenerateKey(session, &arg, attrs.attr, attrs.count, &result->key);
    return TRUE;
}

bool_t
pkcsproc_generatekeypair_1_svc(u_long session, mechanism mech, attributes public_attrs, attributes private_attrs, keypairresult *result,  struct svc_req *rqstp)
{
    CK_MECHANISM arg;
    arg.mechanism      = mech.mechanism;
    arg.pParameter     = mech.parameter.parameter_val;
    arg.ulParameterLen = mech.parameter.parameter_len;
    result->result = local->C_GenerateKeyPair(session, &arg, public_attrs.attr, public_attrs.count,
            private_attrs.attr, private_attrs.count, &result->public_key, &result->private_key);
    return TRUE;
}

bool_t
pkcsproc_seedrandom_1_svc(u_long session, data seed, u_long *result,  struct svc_req *rqstp)
{
    *result = local->C_SeedRandom(session, (unsigned char*)seed.data_val, (unsigned long)seed.data_len);
    return TRUE;
}

bool_t
pkcsproc_generaterandom_1_svc(u_long session, u_long length, randomresult *result,  struct svc_req *rqstp)
{
    result->data.data_len = length;
    result->data.data_val = malloc(result->data.data_len);
    result->result = local->C_GenerateRandom(session, (unsigned char*)result->data.data_val, length);
    return TRUE;
}

int
pkcsprog_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result) {
    xdr_free(xdr_result, result);
    return 1;
}
