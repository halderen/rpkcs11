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
#include "myapplication.h"
#include "mytransport.h"

bool_t
getproperties_xdr(XDR *xdrs, struct getproperties_args* args)
{
    if(!xdr_int16_t(xdrs, &args->nproperties))
        return FALSE;
    for(int i=0; i<args->nproperties; i++) {
        if(!xdr_string(xdrs, &(args->properties->name), 1024) ||
           !xdr_string(xdrs, &(args->properties->value), 1024))
           return FALSE;
    }
    return TRUE;
}

bool_t
randombytes_xdr(XDR *xdrs, struct randombytes_args* args)
{
    if(xdr_u_int(xdrs, &args->length) &&
       xdr_bytes(xdrs, (char**)&(args->bytes), &(args->length), args->length))
        return TRUE;
    else
        return FALSE;
}

bool_t
sha256data_xdr(XDR *xdrs, struct sha256data_args* args)
{
    if(xdr_int16_t(xdrs, &args->session) &&
       xdr_u_int(xdrs, &args->length) &&
       xdr_bytes(xdrs, (char**)&(args->bytes), &(args->length), args->length))
        return TRUE;
    else
        return FALSE;
}

bool_t
sha256hash_xdr(XDR *xdrs, struct sha256hash_args* args)
{
    unsigned int length = 32;
    if(xdr_int16_t(xdrs, &args->session) &&
       xdr_opaque(xdrs, (char*)args->bytes, length))
        return TRUE;
    else
        return FALSE;
}
