#ifndef THETRANSPORT_H
#define THETRANSPORT_H

#include <rpc/xdr.h>

typedef int (*xdr_func_t)(void*);

struct xdr_functable {
    xdr_func_t func;
    size_t size;
    xdrproc_t proc;
};

struct rpc_client;
bool_t xdr_call(XDR *xdrs, uint16_t* funcindex, int (**func)(void*), void** args, int functablesize, struct xdr_functable* functable);
int rpc_call(struct rpc_client* clnt, uint16_t* index, xdr_func_t func, void* args, int functablesize, struct xdr_functable* functable);
struct rpc_client* rpc_client_new();
int rpc_server_run(int rpctablesize, struct xdr_functable* rpctable, int nthreads, int readfd, int writefd);

#endif
