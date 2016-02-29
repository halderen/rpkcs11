#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>
#include "cryptoki_compat/pkcs11.h"
#include "doorrpc.h"
#include "door.h"
#include "server.h"

bool_t
doorrpcproc_null_1_svc(void *result, struct svc_req *rqstp) {
    return TRUE;
}

bool_t
doorrpcproc_call_1_svc(char* method, arguments input, arguments* output,  struct svc_req *rqstp)
{
    CK_RV *resultptr;
    door_setcallbuffer((void*)input.arguments_val);
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
