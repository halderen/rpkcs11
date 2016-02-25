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
