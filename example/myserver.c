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
#include <stdio.h>
#include <syslog.h>
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
    struct channelrpc_server* server;
    server = channelrpc_server_newchannel(NULL, rdfd, wrfd);
    channelrpc_server_register_simple(server, sizeof(srvrpctable)/sizeof(struct xdr_functable), srvrpctable);
    channelrpc_server_run_threaded(server, nthreads);
    channelrpc_server_release(server);
    return 0;
}

int
mydirectserver(struct channelrpc_client* clnt, int buffered)
{
    struct channelrpc_server* server;
    server = channelrpc_server_newchannel(NULL, -1, -1);
    channelrpc_server_register_simple(server, sizeof(srvrpctable)/sizeof(struct xdr_functable), srvrpctable);
    channelrpc_client_connect_direct(clnt, (buffered ? 1 : 2), server);
    return 0;
}
