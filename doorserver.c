#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>
#include "cryptoki_compat/pkcs11.h"
#include "doorrpc.h"
#include "door.h"

static CK_FUNCTION_LIST_PTR local = NULL;

bool_t
doorrpcproc_null_1_svc(void *result, struct svc_req *rqstp) {
    return TRUE;
}

bool_t
doorrpcproc_call_1_svc(char* method, arguments input, arguments* output,  struct svc_req *rqstp)
{
    CK_RV *resultptr;
    door_setcallbuffer(input.arguments_val);
    if(method == NULL || !strcmp(method,"")) {
        output->arguments_len = 0;
        output->arguments_val = NULL;
        return TRUE;
    } else if(!strcmp(method,"C_Initialize")) {
        resultptr = door_OBJ(CK_RV*);
        *resultptr = local->C_Initialize(NULL);
    } else if(!strcmp(method,"C_Finalize")) {
        resultptr = door_OBJ(CK_RV*);
        *resultptr = local->C_Finalize(NULL);
    } else if(!strcmp(method,"C_GetInfo")) {
        local->C_GetInfo(door_OBJ(CK_INFO*));
    } else {
        return FALSE;
    }
    output->arguments_len = input.arguments_len;
    output->arguments_val = malloc(input.arguments_len);
    memcpy(output->arguments_val, input.arguments_val, input.arguments_len);
    door_return((void*)output->arguments_val);
    door_setcallbuffer(NULL);
    return TRUE;
}

int
doorrpcprog_1_freeresult(SVCXPRT *transp, xdrproc_t xdr_result, caddr_t result) {
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

    door_initialize();
    handle = dlopen(argv[1], RTLD_LAZY);
    assert(handle);

    getFunctionList = dlsym(handle, "C_GetFunctionList");
    assert(getFunctionList);
    status = getFunctionList(&local);
    assert(!status);

    return dispatcher();
}
