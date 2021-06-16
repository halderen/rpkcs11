#include "myapplication.h"
#include "mytransport.h"

bool_t
getproperties_xdr(XDR *xdrs, struct getproperties_args* args)
{
    xdr_int16_t(xdrs, &args->nproperties);
    for(int i=0; i<args->nproperties; i++) {
        xdr_string(xdrs, &(args->properties->name), 1024);
        xdr_string(xdrs, &(args->properties->value), 1024);
    }
    return TRUE;
}

bool_t
randombytes_xdr(XDR *xdrs, struct randombytes_args* args)
{
    xdr_u_int(xdrs, &args->length);
    xdr_bytes(xdrs, (char**)&(args->bytes), &(args->length), args->length);
    return TRUE;
}

bool_t
sha256data_xdr(XDR *xdrs, struct sha256data_args* args)
{
    xdr_int16_t(xdrs, &args->session);
    xdr_u_int(xdrs, &args->length);
    xdr_bytes(xdrs, (char**)&(args->bytes), &(args->length), args->length);
    return TRUE;
}

bool_t
sha256hash_xdr(XDR *xdrs, struct sha256hash_args* args)
{
    unsigned int length = 32;
    xdr_int16_t(xdrs, &args->session);
    xdr_opaque(xdrs, (char*)args->bytes, length);
    return TRUE;
}
