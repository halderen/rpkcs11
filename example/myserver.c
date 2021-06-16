#include "channelrpc.h"
#include "myapplication.h"
#include "mytransport.h"
#include "sha256.h"

#if (MODE>0 && !defined(NOMODE))
#define ping ping_impl
#define getproperties getproperties_impl
#define opensession opensession_impl
#define closesession closesession_impl
#define randombytes randombytes_impl
#define sha256data sha256data_impl
#define sha256hash sha256hash_impl
#endif

int
ping_call(void* ptr)
{
    ping();
    return 0;
}

int
getproperties_call(struct getproperties_args* args)
{
    args->nproperties = getproperties(args->nproperties, args->properties);
    return 0;
}

int
opensession_call(int* id)
{
    opensession(id);
    return 0;
}

int
closesession_call(int* id)
{
    closesession(*id);
    return 0;
}

void
randombytes_call(struct randombytes_args* args)
{
    randombytes(args->session, args->bytes, args->length);
}

void
sha256data_call(struct sha256data_args* args)
{
    sha256data(args->session, args->bytes, args->length);
}

void
sha256hash_call(struct sha256hash_args* args)
{
    sha256hash(args->session, args->bytes);
}

struct xdr_functable srvrpctable[] = {
    { (xdr_func_t) ping_call,          sizeof(void),                      (xdrproc_t)xdr_void },
    { (xdr_func_t) getproperties_call, sizeof(struct getproperties_args), (xdrproc_t)getproperties_xdr },
    { (xdr_func_t) opensession_call,   sizeof(uint32_t),                  (xdrproc_t)xdr_int32_t },
    { (xdr_func_t) closesession_call,  sizeof(uint32_t),                  (xdrproc_t)xdr_int32_t },
    { (xdr_func_t) randombytes_call,   sizeof(struct randombytes_args),   (xdrproc_t)randombytes_xdr },
    { (xdr_func_t) sha256data_call,    sizeof(struct sha256data_args),    (xdrproc_t)sha256data_xdr },
    { (xdr_func_t) sha256hash_call,    sizeof(struct sha256hash_args),    (xdrproc_t)sha256hash_xdr },
};

int
myserver(int rdfd, int wrfd, int nthreads)
{
    rpc_server_run(sizeof(srvrpctable)/sizeof(struct xdr_functable), srvrpctable, nthreads, rdfd, wrfd);
    return 0;
}
