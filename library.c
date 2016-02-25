#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

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
        return 1;
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
        return 1;
    } else
        return result;
}

static ck_rv_t
GetInfo(CK_INFO *info) {
    enum clnt_stat retval;
    struct ck_info result;
    retval = pkcsproc_getinfo_1(&result, clnt);
    if (retval != RPC_SUCCESS) {
        clnt_perror(clnt, "call failed");
        return 1;
    } else {
        memcpy(info, &result, sizeof(*info));
        return result.result;
    }
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
	clnt = clnt_create ("localhost", PKCSPROG, PKCSVERS, "udp");
	if (clnt == NULL) {
		clnt_pcreateerror ("localhost");
		exit (1);
	}
#endif
	retval = pkcsproc_null_1(&result, clnt);
	if (retval != RPC_SUCCESS) {
		clnt_perror (clnt, "call failed");
	}
}

__attribute__((destructor))
void
fini(void)
{
#ifndef	DEBUG
	clnt_destroy(clnt);
#endif	 /* DEBUG */
}
