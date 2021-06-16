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

static void
handlenegative(int rcode)
{
    if(rcode < 0) {
        int err = errno;
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

static int
readpartially(int fd, char* buffer, int* index, int size)
{
    int count;
    count = read(fd, &(buffer[*index]), size - *index);
    handlenegative(count);
    *index += count;
    if(*index >= count)
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
struct rpc_client {
    pthread_mutex_t wrmutex;
    pthread_mutex_t rdmutex;
    pthread_mutex_t crmutex;
    int rdfd;
    int wrfd;
    uint32_t activehandler;
    struct clntaction* actions;
};

struct rpc_client*
rpc_client_new(int rdfd, int wrfd)
{
    struct rpc_client* clnt;
    clnt = malloc(sizeof(struct rpc_client));
    handleoom(clnt);
    pthread_mutex_init(&(clnt->wrmutex), NULL);
    pthread_mutex_init(&(clnt->rdmutex), NULL);
    pthread_mutex_init(&(clnt->crmutex), NULL);
    clnt->activehandler = 0;
    clnt->actions = NULL;
    clnt->rdfd = rdfd;
    clnt->wrfd = wrfd;
    return clnt;
}

int
rpc_call(struct rpc_client* clnt, uint16_t* index, xdr_func_t func, void* args, int functablesize, struct xdr_functable* functable)
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

    while(functable[*index].func != func)
        if(*index + 1 >= functablesize) {
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

    rcode = xdrdmem_create(&xdrs, &(action.xdrdmem), XDR_ENCODE);
    handlezero(rcode);
    xdr_setpos(&xdrs, sizeof(uint32_t)*2);
    rcode = xdr_call(&xdrs, index, &func, &args, functablesize, functable);
    handlezero(rcode);
    totalsize = xdr_getpos(&xdrs);
    networkinteger = htonl(totalsize);
    *(uint32_t*)action.xdrdmem.bufdata = networkinteger;
    networkinteger = htonl(mycorrelation);
    *(uint32_t*)(&(action.xdrdmem.bufdata[sizeof(uint32_t)])) = networkinteger;
    xdr_destroy(&xdrs);

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
                    for(actionsptr = &(clnt->actions); *actionsptr; actionsptr = &((*actionsptr)->next)) {
                        if((*actionsptr)->correlation == rdcorrelation) {
                            recvaction = *actionsptr;
                            (*actionsptr)->received = 1;
                            *actionsptr = (*actionsptr)->next;
                            break;
                        }
                    }
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
    rcode = xdr_call(&xdrs, index, &func, &args, functablesize, functable);
    handlezero(rcode);
    xdr_destroy(&xdrs);
    free(action.xdrdmem.bufdata);

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

int
rpc_server_run(int rpctablesize, struct xdr_functable* rpctable, int nthreads, int readfd, int writefd)
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
    
    if(readfd == writefd) {
        rd = wr = nthreads;
    } else {
        rd = nthreads;
        wr = nthreads + 1;
    }

chdir(".."); // BERRY
    rcode = pthread_attr_init(&workerattrs);
    handlenonzero(rcode);
    nfds = nthreads + (rd == wr ? 1 : 2);
    fds = malloc(sizeof(struct pollfd) * nfds);
    handleoom(fds);
    fds[rd].fd = readfd;
    fds[wr].fd = writefd;
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
        workers[i].rpctable = rpctable;
        workers[i].rpctablesize = rpctablesize;
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

        count = poll(fds, nfds, -1);
        handlenegative(count);

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
                }
            }
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
    //pthread_mutex_destroy(&mutex);;
}
