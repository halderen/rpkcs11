#ifndef XDRDMEM_H
#define XDRDMEM_H

#include <rpc/types.h>
#include <rpc/xdr.h>

struct xdrdmem_struct {
    char*  bufdata;
    size_t bufsize;
    size_t bufincr;
};

#define xdrdmem_NULL { (char*)0, 0, 0 };

extern int xdrdmem_create(XDR *xdrs, struct xdrdmem_struct* xdrdmem, enum xdr_op op);

#endif
