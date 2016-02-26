#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>
#include "pkcs11.h"
#include "cryptoki_compat/pkcs11.h"

static CK_FUNCTION_LIST_PTR local = NULL;

bool_t
pkcsproc_null_1_svc(void *result, struct svc_req *rqstp) {
    return TRUE;
}

bool_t
pkcsproc_initialize_1_svc(reserved init_args, ck_rv_t *result, struct svc_req *rqstp) {
    *result = local->C_Initialize(NULL);
    return TRUE;
}

bool_t
pkcsproc_finalize_1_svc(reserved reserved, ck_rv_t *result, struct svc_req *rqstp) {
    *result = local->C_Finalize(NULL);
    return TRUE;
}

bool_t
pkcsproc_getinfo_1_svc(struct ck_info *result, struct svc_req *rqstp) {
    result->result = local->C_GetInfo((CK_INFO*)result);
    return TRUE;
}

bool_t
pkcsproc_getslotlist_1_svc(u_char token_present, slotlist *result, struct svc_req *rqstp) {
    unsigned long len;
    local->C_GetSlotList(token_present, NULL, &len);
    result->slots.slots_val = malloc(sizeof(ck_slot_id_t) * len);
    result->slots.slots_len = len;
    result->result = local->C_GetSlotList(token_present, result->slots.slots_val, &len);
    return TRUE;
}

bool_t
pkcsproc_getslotinfo_1_svc(ck_slot_id_t slot_id, slotinfo *result,  struct svc_req *rqstp)
{
    result->result = local->C_GetSlotInfo(slot_id, (CK_SLOT_INFO*)result);
    return TRUE;
}

bool_t
pkcsproc_gettokeninfo_1_svc(ck_slot_id_t slot_id, tokeninfo *result,  struct svc_req *rqstp)
{
    result->result = local->C_GetTokenInfo(slot_id, (CK_TOKEN_INFO*)result);
    return TRUE;
}

bool_t
pkcsproc_waitforslotevent_1_svc(ck_flags_t flags, reserved arg2, slotevent *result,  struct svc_req *rqstp)
{
    result->result = local->C_WaitForSlotEvent(flags, NULL, (CK_SLOT_ID*)result);
    return TRUE;
}

bool_t
pkcsproc_getmechanismlist_1_svc(ck_slot_id_t slot_id, mechlist *result,  struct svc_req *rqstp)
{
    unsigned long len;
    local->C_GetMechanismList(slot_id, NULL, &len);
    result->mechs.mechs_val = malloc(sizeof(ck_mechanism_type_t) * len);
    result->mechs.mechs_len = len;
    result->result = local->C_GetMechanismList(slot_id, result->mechs.mechs_val, &len);
    return TRUE;
}

bool_t
pkcsproc_getmechanisminfo_1_svc(ck_slot_id_t slot_id, ck_mechanism_type_t type, mechinfo *result,  struct svc_req *rqstp)
{
    return TRUE;
}

bool_t
pkcsproc_inittoken_1_svc(ck_slot_id_t slot_id, buffer pin, char *label, ck_rv_t *result,  struct svc_req *rqstp)
{
    return TRUE;
}

bool_t
pkcsproc_initpin_1_svc(ck_session_handle_t session, buffer pin, ck_rv_t *result,  struct svc_req *rqstp)
{
    return TRUE;
}

bool_t
pkcsproc_setpin_1_svc(ck_session_handle_t session, buffer old_pin, buffer new_pin, ck_rv_t *result,  struct svc_req *rqstp)
{
    return TRUE;
}

bool_t
pkcsproc_opensession_1_svc(ck_slot_id_t slot_id, ck_flags_t flags, sessionresult *result,  struct svc_req *rqstp)
{
    return TRUE;
}

bool_t
pkcsproc_closesession_1_svc(ck_session_handle_t session, ck_rv_t *result,  struct svc_req *rqstp)
{
    return TRUE;
}

bool_t
pkcsproc_closeallsessions_1_svc(ck_slot_id_t slot_id, ck_rv_t *result,  struct svc_req *rqstp)
{
    return TRUE;
}

bool_t
pkcsproc_getsessioninfo_1_svc(ck_session_handle_t session, sessioninfo *result,  struct svc_req *rqstp)
{
    return TRUE;
}

typedef unsigned char *door_unmarshal_t;

void*
door_get_ref(door_unmarshal_t* argref)
{
    void* location;
    ssize_t size = *(ssize_t*)*argref;
    *argref = &(*argref)[sizeof(ssize_t)];
    location = *argref;
    argref = &argref[size];
    return location;
}

void
door_arguments_unmarshal(door_unmarshal_t* argref, buffer arguments)
{
    *argref = arguments.buffer_val;
}

bool_t
pkcsproc_door_1_svc(char* method, buffer arguments, buffer* result,  struct svc_req *rqstp)
{
    door_unmarshal_t argref;
    door_arguments_unmarshal(&argref, arguments);
    if(method == NULL || !strcmp(method,"")) {
        result->buffer_len = 0;
        result->buffer_val = NULL;
        return TRUE;
    } else if(!strcmp(method,"C_Initialize")) {
        local->C_Initialize(NULL);
    } else if(!strcmp(method,"C_Finalize")) {
        local->C_Initialize(NULL);
    } else if(!strcmp(method,"C_GetInfo")) {
        local->C_GetInfo(door_get_ref(&argref));
    } else {
        return FALSE;
    }
    result->buffer_len = arguments.buffer_len;
    result->buffer_val = malloc(arguments.buffer_len);
    memcpy(result->buffer_val, arguments.buffer_val, arguments.buffer_len);
    return TRUE;
}

int
pkcsprog_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result) {
    xdr_free(xdr_result, result);
    return 1;
}

extern int dispatcher(void);

int
main(int argc, char **argv)
{
    void* handle;
    CK_RV status;
    CK_C_GetFunctionList getFunctionList;

    handle = dlopen(argv[1], RTLD_LAZY);
    assert(handle);

    getFunctionList = dlsym(handle, "C_GetFunctionList");
    assert(getFunctionList);
    status = getFunctionList(&local);
    assert(!status);

    return dispatcher();
}
