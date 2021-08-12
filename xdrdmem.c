/*
 * Copyright (c) 2021, NLnet Labs
 * Copyright (c) 2021, A.W. van Halderen
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "config.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <netinet/in.h>
#include "xdrdmem.h"

static int
xdrdmem_resize(XDR* xdrs, u_int len)
{
    int newsize;
    char* newaddr;
    struct xdrdmem_struct* xdrdmem = (struct xdrdmem_struct*) xdrs->x_private;
    len = len - xdrs->x_handy; // how much we still need to allocate
    len = (len + xdrdmem->bufincr-1) / xdrdmem->bufincr; // number of chucks
    len = len * xdrdmem->bufincr; // how much we will increase the buffer
    newsize = len * xdrdmem->bufincr;
    newaddr = realloc(xdrdmem->bufdata, newsize);
    if (newaddr) {
        xdrs->x_base = newaddr + (xdrs->x_base - xdrdmem->bufdata);
        xdrs->x_handy += len;
        xdrdmem->bufsize = newsize;
        xdrdmem->bufdata = newaddr;
        return 1;
    } else
        return 0;
}

static bool_t
xdrdmem_getlong(XDR *xdrs, long *ptr)
{
    if(xdrs->x_handy < sizeof(long))
        return 0;
    xdrs->x_handy -= sizeof(long);
    *ptr = (long)ntohl((u_long)(*((long *)(xdrs->x_base))));
    xdrs->x_base += sizeof(long);
    return 1;
}

static bool_t
xdrdmem_putlong(XDR *xdrs, const long *ptr)
{
    if(xdrs->x_handy < sizeof(long))
        if(!xdrdmem_resize(xdrs, sizeof(long)))
            return 0;
    xdrs->x_handy -= sizeof(long);
    *(long *)xdrs->x_base = (long)htonl((u_long)(*ptr));
    xdrs->x_base += sizeof(long);
    return 1;
}

static bool_t
xdrdmem_getbytes(XDR *xdrs, char* addr, u_int len)
{
    if(xdrs->x_handy < len)
        return 0;
    xdrs->x_handy -= len;
    memcpy(addr, xdrs->x_base, len);
    xdrs->x_base += len;
    return 1;

}

static bool_t
xdrdmem_putbytes(XDR *xdrs, const char* addr, u_int len)
{
    if(xdrs->x_handy < len)
        if(!xdrdmem_resize(xdrs, len))
            return 0;
    xdrs->x_handy -= len;
    memcpy(xdrs->x_base, addr, len);
    xdrs->x_base += len;
    return 1;
}

static u_int
xdrdmem_getpos(XDR *xdrs)
{
    struct xdrdmem_struct* xdrdmem = (struct xdrdmem_struct*) xdrs->x_private;
    return (u_int)(xdrs->x_base - xdrdmem->bufdata);
}

static bool_t
xdrdmem_setpos(XDR *xdrs, u_int pos)
{
    struct xdrdmem_struct* xdrdmem = (struct xdrdmem_struct*) xdrs->x_private;
    if(xdrdmem->bufsize < pos)
        if(!xdrdmem_resize(xdrs, pos - xdrdmem->bufsize))
            return 0;
    xdrs->x_base  = &xdrdmem->bufdata[pos];
    xdrs->x_handy = xdrdmem->bufsize - pos;
    return 1;
}

static int32_t *
xdrdmem_inline(XDR *xdrs, u_int len)
{
    int32_t *buf;
    if (xdrs->x_handy < len)
        if(!xdrdmem_resize(xdrs, len))
            return NULL;
    xdrs->x_handy -= len;
    buf = (int32_t*)(xdrs->x_base);
    xdrs->x_base += len;
    return buf;
}

static void
xdrdmem_destroy(XDR *xdrs)
{
}

static struct xdr_ops xdrdmem_ops = {
    xdrdmem_getlong,
    xdrdmem_putlong,
    xdrdmem_getbytes,
    xdrdmem_putbytes,
    xdrdmem_getpos,
    xdrdmem_setpos,
    xdrdmem_inline,
    xdrdmem_destroy
};

int
xdrdmem_create(XDR *xdrs, struct xdrdmem_struct* xdrdmem, enum xdr_op op)
{
    xdrs->x_op = op;
    xdrs->x_ops = &xdrdmem_ops;
    xdrs->x_private = xdrdmem;
    if(op != XDR_FREE) {
        assert(xdrdmem->bufdata == NULL || xdrdmem->bufsize != 0);
        if(xdrdmem->bufincr == 0 && xdrdmem->bufsize == 0)
            xdrdmem->bufincr = xdrdmem->bufsize = 65000;
        else if(xdrdmem->bufincr == 0)
            xdrdmem->bufincr = xdrdmem->bufsize;
        else if(xdrdmem->bufsize == 0)
            xdrdmem->bufsize = 65000;
        if(xdrdmem->bufdata == NULL && op != XDR_FREE)
            xdrdmem->bufdata = malloc(xdrdmem->bufsize);
        xdrs->x_base = xdrdmem->bufdata;
        xdrs->x_handy = xdrdmem->bufsize;
        if(xdrdmem->bufdata == NULL)
            return 0;
    }
    return 1;
}
