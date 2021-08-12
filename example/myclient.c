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
#include <string.h>
#include <memory.h>
#include <assert.h>
#include "channelrpc.h"
#include "myapplication.h"
#include "mytransport.h"

static struct channelrpc_client* clnt = NULL;

#if (MODE < 1 && !defined(NOMODE))
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
    clnt = channelrpc_client_newchannel(NULL, sizeof(clntrpctable)/sizeof(struct xdr_functable), clntrpctable);
    channelrpc_client_connect_socket(clnt, rdfd, wrfd);
    assert(clnt);
    return 0;
}

#if (!defined(NOMODE) && MODE < 3)
int
mydirectclient(void)
{
    clnt = channelrpc_client_newchannel(NULL, sizeof(clntrpctable)/sizeof(struct xdr_functable), clntrpctable);
    assert(clnt);
#if (MODE < 2)
    mydirectserver(clnt, 0);
#else
    mydirectserver(clnt, 1);
#endif
    assert(clnt);
    return 0;
}
#endif

void
myclose(void)
{
    channelrpc_client_release(clnt);
}

void
ping(void)
{
    static uint16_t ping_index = 0;
    int dummy;
    channelrpc_call(clnt, &ping_index, (xdr_func_t)ping, &dummy);
    assert(clnt);
    return;
}

int
getproperties(int nproperties, struct property* properties)
{
    static uint16_t getproperties_index = 0;
    struct getproperties_args args = { nproperties, properties };
    channelrpc_call(clnt, &getproperties_index, (xdr_func_t)getproperties, &args);
    return args.nproperties;
}

int
opensession(int* session)
{
    static uint16_t opensession_index = 0;
    int rcode;
    rcode = channelrpc_call(clnt, &opensession_index, (xdr_func_t)opensession, session);
    return rcode;
}

int
closesession(int session)
{
    static uint16_t closesession_index = 0;
    int rcode;
    rcode = channelrpc_call(clnt, &closesession_index, (xdr_func_t)closesession, &session);
    return rcode;
}

void
randombytes(int session, uint8_t *bytes, int length)
{
    static uint16_t randombytes_index = 0;
    struct randombytes_args args = { session, length, bytes };
    channelrpc_call(clnt, &randombytes_index, (xdr_func_t)randombytes, &args);
    assert(clnt);
}

void
sha256data(int session, uint8_t* bytes, int length)
{
    static uint16_t sha256data_index = 0;
    struct sha256data_args args = { session, length, bytes };
    assert(clnt);
    channelrpc_call(clnt, &sha256data_index, (xdr_func_t)sha256data, &args);
}

void
sha256hash(int session, uint8_t hash[32])
{
    static uint16_t sha256hash_index = 0;
    struct sha256hash_args args;
    args.session = session;
    memcpy(args.bytes, hash, sizeof(args.bytes));
    channelrpc_call(clnt, &sha256hash_index, (xdr_func_t)sha256hash, &args);
}
