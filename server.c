#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include "pkcs11.h"
#include "server.h"

CK_FUNCTION_LIST_PTR local = NULL;

extern void pkcsprog_1(struct svc_req *rqstp, register SVCXPRT *transp);

int
main(int argc, char **argv)
{
    void* handle;
    CK_RV status;
    CK_C_GetFunctionList getFunctionList;
    register SVCXPRT *transp;

    handle = dlopen(argv[1], RTLD_LAZY);
    assert(handle);

    getFunctionList = dlsym(handle, "C_GetFunctionList");
    assert(getFunctionList);
    status = getFunctionList(&local);
    assert(!status);

    if ((transp = svcudp_create(RPC_ANYSOCK)) == NULL) {
        return 1;
    }
    if ((transp = svctcp_create(RPC_ANYSOCK, 0, 0)) == NULL) {
        return 2;
    }

    pmap_unset(PKCSPROG, PKCSVERS);
    if ((transp = svcudp_create(RPC_ANYSOCK)) == NULL) {
        return 5;
    }
    if (!svc_register(transp, PKCSPROG, PKCSVERS, pkcsprog_1, IPPROTO_UDP)) {
        return 6;
    }
    if ((transp = svctcp_create(RPC_ANYSOCK, 0, 0)) == NULL) {
        return 7;
    }
    if (!svc_register(transp, PKCSPROG, PKCSVERS, pkcsprog_1, IPPROTO_TCP)) {
        return 8;
    }

    svc_run();
    
    exit(0);
}
