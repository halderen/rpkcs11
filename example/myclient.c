#include <string.h>
#include <memory.h>
#include "channelrpc.h"
#include "myapplication.h"
#include "mytransport.h"

static struct rpc_client* clnt;

#if (MODE < 3 && !defined(NOMODE))
#define ping ping_clnt
#define getproperties getproperties_clnt
#define opensession opensession_clnt
#define closesession closesession_clnt
#define randombytes randombytes_clnt
#define sha256data sha256data_clnt
#define sha256hash sha256hash_clnt
#endif

struct xdr_functable clntrpctable[] = {
    { (xdr_func_t) ping,          sizeof(void),                      (xdrproc_t)xdr_void },
    { (xdr_func_t) getproperties, sizeof(struct getproperties_args), (xdrproc_t)getproperties_xdr },
    { (xdr_func_t) opensession,   sizeof(uint32_t),                  (xdrproc_t)xdr_int32_t },
    { (xdr_func_t) closesession,  sizeof(uint32_t),                  (xdrproc_t)xdr_int32_t },
    { (xdr_func_t) randombytes,   sizeof(struct randombytes_args),   (xdrproc_t)randombytes_xdr },
    { (xdr_func_t) sha256data,    sizeof(struct sha256data_args),    (xdrproc_t)sha256data_xdr },
    { (xdr_func_t) sha256hash,    sizeof(struct sha256hash_args),    (xdrproc_t)sha256hash_xdr },
};


int
myclient(int rdfd, int wrfd)
{
    clnt = rpc_client_new(rdfd, wrfd);
    return 0;
}

void
ping(void)
{
    static uint16_t ping_index = 0;
    int dummy;
    rpc_call(clnt, &ping_index, (xdr_func_t)ping, &dummy, sizeof(clntrpctable)/sizeof(struct xdr_functable), clntrpctable);
    return;
}

int
getproperties(int nproperties, struct property* properties)
{
    static uint16_t getproperties_index = 0;
    struct getproperties_args args = { nproperties, properties };
    rpc_call(clnt, &getproperties_index, (xdr_func_t)getproperties, &args, sizeof(clntrpctable)/sizeof(struct xdr_functable), clntrpctable);
    return args.nproperties;
}

int
opensession(int* session)
{
    static uint16_t opensession_index = 0;
    int rcode;
    rcode = rpc_call(clnt, &opensession_index, (xdr_func_t)opensession, session, sizeof(clntrpctable)/sizeof(struct xdr_functable), clntrpctable);
    return rcode;
}

int
closesession(int session)
{
    static uint16_t closesession_index = 0;
    int rcode;
    rcode = rpc_call(clnt, &closesession_index, (xdr_func_t)closesession, &session, sizeof(clntrpctable)/sizeof(struct xdr_functable), clntrpctable);
    return rcode;
}

void
randombytes(int session, uint8_t *bytes, int length)
{
    static uint16_t randombytes_index = 0;
    struct randombytes_args args = { session, length, bytes };
    rpc_call(clnt, &randombytes_index, (xdr_func_t)randombytes, &args, sizeof(clntrpctable)/sizeof(struct xdr_functable), clntrpctable);
}

void
sha256data(int session, uint8_t* bytes, int length)
{
    static uint16_t sha256data_index = 0;
    struct sha256data_args args = { session, length, bytes };
    rpc_call(clnt, &sha256data_index, (xdr_func_t)sha256data, &args, sizeof(clntrpctable)/sizeof(struct xdr_functable), clntrpctable);
}

void
sha256hash(int session, uint8_t hash[32])
{
    static uint16_t sha256hash_index = 0;
    struct sha256hash_args args;
    args.session = session;
    memcpy(args.bytes, hash, sizeof(args.bytes));
    rpc_call(clnt, &sha256hash_index, (xdr_func_t)sha256hash, &args, sizeof(clntrpctable)/sizeof(struct xdr_functable), clntrpctable);
}
