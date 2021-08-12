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
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <pthread.h>
#include <poll.h>
#include <arpa/inet.h>
#include <rpc/xdr.h>
#include <errno.h>
#include "channelrpc.h"
#include "xdrdmem.h"

int (*channelrpc_call)(struct channelrpc_client*, uint16_t*, xdr_func_t, void*);

struct channelrpc_server {
    int readfd;
    int writefd;
    int rpctablesize;
    struct xdr_functable* rpctable;
};

static void
handlenegative(int rcode)
{
    if(rcode < 0) {
        int err = errno;
        if(err == EAGAIN || err == EINTR)
            return;
        fprintf(stderr,"Failed %s (%d)\n",strerror(err),err);
        fflush(stderr);
        abort();
    }
}

static void
handleoom(void* ptr)
{
    if(!ptr) {
        fprintf(stderr,"Out of memory\n");
        fflush(stderr);
        abort();
    }
}

static void
handlenonzero(int rcode)
{
    if(rcode) {
        int err = errno;
        fprintf(stderr,"Failed %s (%d)\n",strerror(err),err);
        fflush(stderr);
        abort();
    }    
}

static void
handlezero(int rcode)
{
    if(!rcode) {
        int err = errno;
        fprintf(stderr,"Failed %s (%d)\n",strerror(err),err);
        fflush(stderr);
        abort();
    }    
}

static void
handleerror()
{
    int err = errno;
    fprintf(stderr,"Failed %s (%d)\n",strerror(err),err);
    fflush(stderr);
    abort();
}

static int
readpartially(int fd, char* buffer, int* index, int size)
{
    int count;
    count = read(fd, &(buffer[*index]), size - *index);
    handlenegative(count);
    if(count == 0) {
        *index = 0;
        return 0;
    }
    *index += count;
    if(*index >= size)
        return 1;
    else
        return 0;
}

static void
writefully(int fd, char* buffer, int size)
{
    int count;
    int index = 0;
    while(index < size) {
        count = write(fd, &(buffer[index]), size - index);
        handlenegative(count);
        index += count;
    }
}

static void
readfully(int fd, char* buffer, int size)
{
    int count;
    int index = 0;
    while(index < size) {
        count = read(fd, &(buffer[index]), size - index);
        handlenegative(count);
        index += count;
    }
}

bool_t
xdr_call(XDR *xdrs, uint16_t* funcindex, xdr_func_t* func, void** args, int functablesize, struct xdr_functable* functable)
{
    if(!xdr_uint16_t(xdrs, funcindex)) {
        return 0;
    }
    if(*funcindex < 0 || *funcindex >= functablesize) {
        return 0;
    }
    *func = functable[*funcindex].func;
    if(!xdr_reference(xdrs, (char**)args, functable[*funcindex].size, functable[*funcindex].proc)) {
        return 0;
    }
    //if(xdrs->x_op == XDR_FREE)
    //    free(rpcargs);
    return 1;
}

static uint32_t correlationcounter = 0;

struct clntaction;
struct clntaction {
    //char* buffer;
    uint32_t correlation;
    //uint32_t size;
    int received;
    pthread_cond_t cond;
    struct xdrdmem_struct xdrdmem;
    struct clntaction* next;
};

struct channelrpc_client {
    int functablesize;
    struct xdr_functable* functable;
    pthread_mutex_t wrmutex;
    pthread_mutex_t rdmutex;
    pthread_mutex_t crmutex;
    int rdfd;
    int wrfd;
    uint32_t activehandler;
    struct clntaction* actions;
    struct channelrpc_server* direct;
};

static int
encodebuffer(struct channelrpc_client* clnt, struct xdrdmem_struct* xdrdmem, uint16_t* index, xdr_func_t func, void* args, uint32_t correlation)
{
    XDR xdrs;
    int32_t networkinteger;
    int rcode;
    int totalsize;
    rcode = xdrdmem_create(&xdrs, xdrdmem, XDR_ENCODE);
    handlezero(rcode);
    xdr_setpos(&xdrs, sizeof(uint32_t)*2);
    rcode = xdr_call(&xdrs, index, &func, &args, clnt->functablesize, clnt->functable);
    handlezero(rcode);
    totalsize = xdr_getpos(&xdrs);
    networkinteger = htonl(totalsize);
    *(uint32_t*)(xdrdmem->bufdata) = networkinteger;
    networkinteger = htonl(correlation);
    *(uint32_t*)(&(xdrdmem->bufdata[sizeof(uint32_t)])) = networkinteger;
    xdr_destroy(&xdrs);
    return totalsize;
}

static uint32_t
decodebuffer(struct channelrpc_client* clnt, struct xdrdmem_struct* xdrdmem, uint16_t* index, xdr_func_t func, void* args, int totalsize)
{
    XDR xdrs;
    int32_t networkinteger;
    int rcode;
    uint32_t correlation;
    networkinteger = *(uint32_t*)(xdrdmem->bufdata);
    assert(totalsize <= 0 || totalsize == ntohl(networkinteger));
    networkinteger = *(uint32_t*)(&(xdrdmem->bufdata[sizeof(uint32_t)]));
    correlation = ntohl(networkinteger);
    rcode = xdrdmem_create(&xdrs, xdrdmem, XDR_DECODE);
    handlezero(rcode);
    xdr_setpos(&xdrs, sizeof(uint32_t)*2);
    rcode = xdr_call(&xdrs, index, &func, &args, clnt->functablesize, clnt->functable);
    handlezero(rcode);
    xdr_destroy(&xdrs);
    return correlation;
}

int
channelrpc_call_impl(struct channelrpc_client* clnt, uint16_t* index, xdr_func_t func, void* args)
{
    int32_t networkinteger;
    int totalsize;
    int rcode;
    uint32_t mycorrelation;
    uint32_t rdcorrelation;
    XDR xdrs;
    struct clntaction action;
    struct clntaction** actionsptr;
    struct clntaction* recvaction;
    char header[sizeof(uint32_t)*2];

    while(clnt->functable[*index].func != func)
        if(*index + 1 >= clnt->functablesize) {
            *index = 0;
            break;
        } else
            ++(*index);

    rcode = pthread_mutex_lock(&(clnt->crmutex));
    handlenonzero(rcode);
    mycorrelation = ++correlationcounter;
    action.correlation = mycorrelation;
    memset(&(action.xdrdmem), 0, sizeof(action.xdrdmem));
    action.received = 0;
    rcode = pthread_cond_init(&action.cond, NULL);
    handlenonzero(rcode);
    action.next = clnt->actions;
    clnt->actions = &action;
    rcode = pthread_mutex_unlock(&(clnt->crmutex));
    handlenonzero(rcode);

    totalsize = encodebuffer(clnt, &(action.xdrdmem), index, func, args, mycorrelation);
    
    rcode = pthread_mutex_lock(&(clnt->wrmutex));
    handlenonzero(rcode);
    writefully(clnt->wrfd, action.xdrdmem.bufdata, totalsize);
    rcode = pthread_mutex_unlock(&(clnt->wrmutex));
    handlenonzero(rcode);

    rcode = pthread_mutex_lock(&(clnt->rdmutex));
    handlenonzero(rcode);
    
    pthread_mutex_lock(&(clnt->crmutex));
    while(!action.received) {
        if(!clnt->activehandler) {
            clnt->activehandler = mycorrelation;
                pthread_mutex_unlock(&(clnt->crmutex));
                do {
                    readfully(clnt->rdfd, header, sizeof (uint32_t)*2);
                    networkinteger = *(uint32_t*)header;
                    totalsize = ntohl(networkinteger);
                    networkinteger = *(uint32_t*)(&(header[sizeof (uint32_t)]));
                    rdcorrelation = ntohl(networkinteger);

                    rcode = pthread_mutex_lock(&(clnt->crmutex));
                    handlenonzero(rcode);
                    recvaction = NULL;
                    for(actionsptr = &(clnt->actions); *actionsptr; actionsptr = &((*actionsptr)->next)) {
                        if((*actionsptr)->correlation == rdcorrelation) {
                            recvaction = *actionsptr;
                            (*actionsptr)->received = 1;
                            *actionsptr = (*actionsptr)->next;
                            break;
                        }
                    }
                    assert(recvaction);
                    rcode = pthread_mutex_unlock(&(clnt->crmutex));
                    handlenonzero(rcode);

                    if(recvaction->xdrdmem.bufsize < totalsize) {
                        recvaction->xdrdmem.bufdata = realloc(recvaction->xdrdmem.bufdata, totalsize);
                        handleoom(recvaction->xdrdmem.bufdata);
                    }
                    recvaction->xdrdmem.bufsize = totalsize; // actually the buffer may be larger
                    memcpy(recvaction->xdrdmem.bufdata, header, sizeof(uint32_t) * 2);

                    readfully(clnt->rdfd, &(recvaction->xdrdmem.bufdata[sizeof (uint32_t)*2]), totalsize - sizeof (uint32_t)*2);

                    if(!action.received) {
                        // This was for a different thread
                        pthread_cond_signal(&(recvaction->cond));
                    }
                } while(!action.received);
                pthread_mutex_lock(&(clnt->crmutex));
                clnt->activehandler = 0;
        } else {
            pthread_cond_wait(&(action.cond), &(clnt->crmutex));
        }
    }
    rcode = pthread_mutex_unlock(&(clnt->crmutex));
    handlenonzero(rcode);
    rcode = pthread_mutex_unlock(&(clnt->rdmutex));
    handlenonzero(rcode);

    networkinteger = *(uint32_t*)action.xdrdmem.bufdata;
    totalsize = ntohl(networkinteger);
    networkinteger = *(uint32_t*)(&(action.xdrdmem.bufdata[sizeof(uint32_t)]));
    rdcorrelation = ntohl(networkinteger);
    assert(rdcorrelation == mycorrelation);

    rcode = xdrdmem_create(&xdrs, &(action.xdrdmem), XDR_DECODE);
    handlezero(rcode);
    xdr_setpos(&xdrs, sizeof(uint32_t)*2);
    rcode = xdr_call(&xdrs, index, &func, &args, clnt->functablesize, clnt->functable);
    handlezero(rcode);
    xdr_destroy(&xdrs);
    free(action.xdrdmem.bufdata);

    return 0;
}

int
channelrpc_call_direct(struct channelrpc_client* clnt, uint16_t* index, xdr_func_t func, void* args)
{
    assert(*index < clnt->functablesize);
    
    while(clnt->functable[*index].func != func)
        if(*index + 1 >= clnt->functablesize) {
            *index = 0;
            break;
        } else
            ++(*index);

    /* server executing */
    clnt->direct->rpctable[*index].func(args);
    
    return 0;
}

int
channelrpc_call_direct_buffered(struct channelrpc_client* clnt, uint16_t* index, xdr_func_t func, void* args)
{
    int32_t networkinteger;
    int totalsize;
    int correlation = 0;
    int rcode;
    XDR xdrs;
    struct xdrdmem_struct xdrdmem1 = xdrdmem_NULL;
    struct xdrdmem_struct xdrdmem2 = xdrdmem_NULL;
    void* rpcargs = NULL;
    uint16_t rpcindex;
    xdr_func_t rpcfunc;

    assert(*index < clnt->functablesize);
    
    while(clnt->functable[*index].func != func)
        if(*index + 1 >= clnt->functablesize) {
            *index = 0;
            break;
        } else
            ++(*index);

    /* client sending side */
    memset(&xdrdmem1, 0, sizeof(xdrdmem1));
    totalsize = encodebuffer(clnt, &xdrdmem1, index, func, args, correlation);

    /* server receiving side*/
    xdrdmem2.bufdata = malloc(totalsize);
    xdrdmem2.bufsize = totalsize;
    memcpy(xdrdmem2.bufdata, xdrdmem1.bufdata, totalsize);
    rcode = xdrdmem_create(&xdrs, &xdrdmem2, XDR_DECODE);
    xdr_setpos(&xdrs, sizeof(uint32_t)*2);
    rpcargs = NULL;
    rcode = xdr_call(&xdrs, &rpcindex, &rpcfunc, &rpcargs, clnt->direct->rpctablesize, clnt->direct->rpctable);
    assert(rpcargs);
    xdr_destroy(&xdrs);

    assert(*index == rpcindex);

    /* server executing */
    assert(*index == rpcindex);
    clnt->direct->rpctable[rpcindex].func(rpcargs);

    /* server sending side*/
    totalsize = encodebuffer(clnt, &xdrdmem2, &rpcindex, rpcfunc, rpcargs, correlation);
    rcode = xdrdmem_create(&xdrs, NULL, XDR_FREE);
    rcode = xdr_call(&xdrs, &rpcindex, &rpcfunc, &rpcargs, clnt->direct->rpctablesize, clnt->direct->rpctable);
    xdr_destroy(&xdrs);

    /* client receiving side */
    if(xdrdmem1.bufsize < totalsize)
        xdrdmem1.bufdata = realloc(xdrdmem1.bufdata, totalsize);
    xdrdmem1.bufsize = totalsize;
    memcpy(xdrdmem1.bufdata, xdrdmem2.bufdata, totalsize);
    decodebuffer(clnt, &xdrdmem1, index, func, args, totalsize);
    free(xdrdmem2.bufdata);
    free(xdrdmem1.bufdata);

    return 0;
}

struct channelrpc_client*
channelrpc_client_newchannel(__attribute__((unused)) void* conf, int functablesize, struct xdr_functable* functable)
{
    struct channelrpc_client* clnt;
    clnt = malloc(sizeof(struct channelrpc_client));
    handleoom(clnt);
    clnt->functable = functable;
    clnt->functablesize = functablesize;
    pthread_mutex_init(&(clnt->wrmutex), NULL);
    pthread_mutex_init(&(clnt->rdmutex), NULL);
    pthread_mutex_init(&(clnt->crmutex), NULL);
    clnt->activehandler = 0;
    clnt->actions = NULL;
    clnt->rdfd = -1;
    clnt->wrfd = -1;
    channelrpc_call = channelrpc_call_impl;
    clnt->direct = NULL;
    return clnt;
}

void
channelrpc_client_connect_socket(struct channelrpc_client* clnt, int rdfd, int wrfd)
{
    clnt->rdfd = rdfd;
    clnt->wrfd = wrfd;
}

void
channelrpc_client_connect_direct(struct channelrpc_client* clnt, int method, struct channelrpc_server* server, ...)
{
    clnt->direct = server;
    if(method == 0) {
        clnt->direct = NULL;
        channelrpc_call = channelrpc_call_impl;        
    } else if(method == 1) {
        channelrpc_call = channelrpc_call_direct;
    } else if(method == 2) {
        channelrpc_call = channelrpc_call_direct_buffered;
    } else {
        clnt->direct = NULL;
    }
}

int
channelrpc_client_release(struct channelrpc_client* handle)
{
    if(!handle)
        return 1;
    if(handle->direct)
        channelrpc_server_release(handle->direct);
    free(handle);
    return 0;
}

struct worker {
    pthread_t thr;
    pthread_barrier_t notifier;
    int fdpair[2];
    int idle;
    uint32_t id;
    char* buffer;
    size_t size;
    struct xdr_functable* rpctable;
    int rpctablesize;
}* workers;

static void*
workerroutine(void* data)
{
    int ch, count, rcode;
    uint32_t networkint;
    int (*rpcfunc)(void*) = NULL;
    void *rpcargs;
    struct worker* worker = (struct worker*)data;
    uint16_t rpcindex;
    XDR xdrs;

    for(;;) {
        pthread_barrier_wait(&(worker->notifier));

        struct xdrdmem_struct xdrdmem = xdrdmem_NULL;
        xdrdmem.bufdata = worker->buffer;
        xdrdmem.bufsize = worker->size;
        rcode = xdrdmem_create(&xdrs, &xdrdmem, XDR_DECODE);
        handlezero(rcode);
        xdr_setpos(&xdrs, sizeof(uint32_t)*2);
        rpcfunc = NULL;
        rpcargs = NULL;
        rpcindex = 0;

        rcode = xdr_call(&xdrs, &rpcindex, &rpcfunc, &rpcargs, worker->rpctablesize, worker->rpctable);
        handlezero(rcode);
        xdr_destroy(&xdrs);

        assert(rpcfunc);
        rpcfunc(rpcargs);

        xdr_setpos(&xdrs, 0);
        rcode = xdrdmem_create(&xdrs, &xdrdmem, XDR_ENCODE);
        handlezero(rcode);
        xdr_setpos(&xdrs, sizeof(uint32_t)*2);
        rcode = xdr_call(&xdrs, &rpcindex, &rpcfunc, &rpcargs, worker->rpctablesize, worker->rpctable);
        handlezero(rcode);
        worker->buffer = xdrdmem.bufdata;
        worker->size   = xdr_getpos(&xdrs);
        xdr_destroy(&xdrs);
        networkint = htonl(worker->size);
        memcpy(worker->buffer, &networkint, sizeof(networkint));
        networkint = htonl(worker->id);
        memcpy(&(worker->buffer[sizeof(networkint)]), &networkint, sizeof(networkint));        

        rcode = xdrdmem_create(&xdrs, &xdrdmem, XDR_FREE);
        handlezero(rcode);
        xdr_setpos(&xdrs, sizeof(uint32_t)*2);
        rcode = xdr_call(&xdrs, &rpcindex, &rpcfunc, &rpcargs, worker->rpctablesize, worker->rpctable);
        xdr_destroy(&xdrs);

        ch = 0;
        count = write(worker->fdpair[1], &ch, 1);
        assert(count == 1);
    }
}

struct channelrpc_server*
channelrpc_server_newchannel(__attribute__((unused)) void* future, int readfd, int writefd)
{
    struct channelrpc_server* server;
    server = malloc(sizeof(struct channelrpc_server));
    if(!server)
        return NULL;
    server->readfd  = readfd;
    server->writefd = writefd;
    server->rpctablesize = 0;
    server->rpctable = NULL;
    return server;
}

int
channelrpc_server_release(struct channelrpc_server* handle)
{
    if(!handle)
        return 0;
    free(handle);
    return 0;
}

int
channelrpc_server_register_simple(struct channelrpc_server* handle, int rpctablesize, struct xdr_functable* rpctable)
{
    handle->rpctablesize = rpctablesize;
    handle->rpctable = rpctable;
    return 0;
}

int
channelrpc_server_run_threaded(struct channelrpc_server* handle, int nthreads)
{
    struct pollfd *fds;
    nfds_t nfds;
    struct worker* idleworker;
    char ch;
    size_t readingsize = 0;
    size_t writingsize = 0;
    int readingindex = 0;
    int writingindex = 0;
    char* readingbuffer = NULL;
    char* writingbuffer = NULL;
    char header[8];
    int headerindex = 0;
    ssize_t count;
    pthread_attr_t workerattrs;
    int rcode;
    int correlation;
    pthread_mutex_t mutex;
    int rd, wr;
    
    if(handle->readfd == handle->writefd) {
        rd = wr = nthreads;
    } else {
        rd = nthreads;
        wr = nthreads + 1;
    }

    rcode = pthread_attr_init(&workerattrs);
    handlenonzero(rcode);
    nfds = nthreads + (rd == wr ? 1 : 2);
    fds = malloc(sizeof(struct pollfd) * nfds);
    handleoom(fds);
    fds[rd].fd = handle->readfd;
    fds[wr].fd = handle->writefd;
    workers = malloc(sizeof(struct worker) * nthreads);
    handleoom(workers);
    rcode = pthread_mutex_init(&mutex, NULL);
    handlenonzero(rcode);
    
    for(int i = 0; i<nthreads; i++) {
        rcode = pthread_barrier_init(&(workers[i].notifier), NULL, 2);
        handlenonzero(rcode);
        rcode = pthread_create(&(workers[i].thr), &workerattrs, workerroutine, &workers[i]);
        handlenonzero(rcode);
        rcode = pipe(workers[i].fdpair);
        handlenonzero(rcode);
        workers[i].idle = 1;
        workers[i].id = 0;
        workers[i].size = 0;
        workers[i].buffer = NULL;
        workers[i].rpctable = handle->rpctable;
        workers[i].rpctablesize = handle->rpctablesize;
        fds[i].fd = workers[i].fdpair[0];
    }

    for(;;) {
        idleworker = NULL;
        fds[rd].events = 0;
        fds[wr].events = 0;
        for(int i = 0; i<nthreads; i++) {
            fds[i].events = 0;
            fds[i].revents = 0;
            if(workers[i].idle) {
                fds[rd].events |= POLLIN;
                if(!idleworker)
                    idleworker = &workers[i];
            } else {
                fds[i].events |= POLLIN;
            }
        }
        if(writingbuffer) {
            fds[wr].events |= POLLOUT;
        }
        fds[rd].events |= POLLHUP | POLLERR;
        fds[wr].events |= POLLHUP | POLLERR;

        count = poll(fds, nfds, -1);
        handlenegative(count);

        if(fds[rd].revents & POLLHUP || fds[rd].revents & POLLERR ||
           fds[wr].revents & POLLHUP || fds[wr].revents & POLLERR) {
            break;
        }
        if(fds[wr].revents & POLLOUT) { 
            if(writingbuffer) {
                count = write(fds[wr].fd, &(writingbuffer[writingindex]), writingsize-writingindex);
                if(count > 0) {
                    writingindex += count;
                    if(writingindex == writingsize) {
                        free(writingbuffer);
                        writingbuffer = NULL;
                    }
                }
            }
        }
        if(fds[rd].revents & POLLIN) {
            if(!readingbuffer) {
                if(readpartially(fds[rd].fd, header, &headerindex, sizeof(header))) {
                    headerindex = 0;
                    readingsize = ntohl(*(uint32_t*)header);
                    correlation = ntohl(*(uint32_t*)(&(header[sizeof(uint32_t)])));
                    assert(readingsize >= sizeof(uint32_t) * 2);
                    readingbuffer = malloc(readingsize);
                    handleoom(readingbuffer);
                    memcpy(readingbuffer, header, sizeof(header));
                    readingindex = sizeof(uint32_t) * 2;
                } else if(headerindex == 0) {
                    // Failed to read anything at this time
                    break;
                }
            } else {
                if(readpartially(fds[rd].fd, readingbuffer, &readingindex, readingsize)) {
                    assert(idleworker);
                    idleworker->buffer = readingbuffer;
                    assert(readingbuffer);
                    idleworker->size = readingsize;
                    idleworker->id = correlation;
                    idleworker->idle = 0;
                    readingbuffer = NULL;
                    pthread_barrier_wait(&idleworker->notifier);
                    readingbuffer = NULL;
                } else if(readingindex == 0) {
                    // Failed to read anything at this time
                    break;
                }
            }
        }
        for(int i=0; i<nthreads; i++) {
            if(!writingbuffer) {
                if(fds[i].revents & POLLIN) {
                    count = read(fds[i].fd, &ch, 1);
                    assert(count == 1);
                    writingbuffer = workers[i].buffer;
                    assert(writingbuffer);
                    writingsize = workers[i].size;
                    writingindex = 0;
                    workers[i].idle = 1;
                    workers[i].buffer = NULL;
                    workers[i].size = 0;
                    workers[i].id = 0;
                }
            }
        }
    }

    for(int i = 0; i<nthreads; i++) {
        pthread_kill(workers[i].thr, SIGTERM);
        //pthread_barrier_destroy(&workers[i].notifier);
        close(workers[i].fdpair[0]);
        close(workers[i].fdpair[1]);
    }
    pthread_attr_destroy(&workerattrs);
    free(fds);
    free(workers);
    //pthread_mutex_destroy(&mutex);;
}
