#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>
#include "cryptoki_compat/pkcs11.h"

int
main(int argc, char *argv[])
{
    void* handle = NULL;
    CK_C_GetFunctionList getFunctionList;
    CK_FUNCTION_LIST_PTR pkcs11 = NULL;
    CK_INFO info;
    CK_RV status;
    if (argc>1) {
        handle = dlopen(argv[1],RTLD_NOW); 
        assert(handle);
    }
    getFunctionList = dlsym(handle, "C_GetFunctionList");
    assert(getFunctionList);
    status = getFunctionList(&pkcs11);
    assert(!status);
    status = pkcs11->C_Initialize(NULL);
    assert(!status || status == CKR_CRYPTOKI_ALREADY_INITIALIZED);
    status = pkcs11->C_GetInfo(&info);
    assert(!status);
    printf("GetInfo:\n");
    printf("  cryptoki version       : %d.%d\n",info.cryptokiVersion.major,info.cryptokiVersion.minor);
    printf("  manufacturer           : %.*s\n",(int)sizeof(info.manufacturerID),info.manufacturerID);
    printf("  flags                  : %lu\n",info.flags);
    printf("  library description    : %.*s\n",(int)sizeof(info.libraryDescription),info.libraryDescription);
    printf("  library version        : %d.%d\n",info.libraryVersion.major,info.libraryVersion.minor);
    status = pkcs11->C_Finalize(NULL);
    assert(!status);
    return 0;
}
