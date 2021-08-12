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
#ifndef THETRANSPORT_H
#define THETRANSPORT_H

#include <rpc/xdr.h>

typedef int (*xdr_func_t)(void*);

struct xdr_functable {
    xdr_func_t func;
    size_t size;
    xdrproc_t proc;
};

struct channelrpc_client;
struct channelrpc_server;

extern bool_t xdr_call(XDR *xdrs, uint16_t* funcindex, int (**func)(void*), void** args, int functablesize, struct xdr_functable* functable);

// This being a function pointer rather than a direct call, makes this worst case 2% slower
extern int (*channelrpc_call)(struct channelrpc_client* clnt, uint16_t* index, xdr_func_t func, void* args);

extern struct channelrpc_client* channelrpc_client_newchannel(void* future, int functablesize, struct xdr_functable* functable);
extern void channelrpc_client_connect_socket(struct channelrpc_client* clnt, int rdfd, int wrfd);
extern void channelrpc_client_connect_direct(struct channelrpc_client* clnt, int method, struct channelrpc_server* server, ...);
extern int channelrpc_client_release(struct channelrpc_client* handle);

extern struct channelrpc_server* channelrpc_server_newchannel(void* future, int rdfd, int wrfd);
extern int channelrpc_server_register_simple(struct channelrpc_server* handle, int rpctablesize, struct xdr_functable* rpctable);
extern int channelrpc_server_run_threaded(struct channelrpc_server* handle, int nthreads);
extern int channelrpc_server_release(struct channelrpc_server* handle);

#endif
