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
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <assert.h>
#include <netdb.h>
#include "myapplication.h"
#include "mytransport.h"

static int nthreads;
static int niters;
static pthread_barrier_t barrier;

#if (defined(MODE) && !defined(NOMODE))
static pthread_t serverthread;

struct serverdata {
    int rdfd;
    int wrfd;
    int nthreads;
};

static void*
serverroutine(void*data)
{
    struct serverdata* serverdata = (struct serverdata*) data;
    myserver(serverdata->rdfd, serverdata->wrfd, serverdata->nthreads);
    return NULL;
}

static int
connectinternal(int serverthreads)
{
    int fds1[2];
    int fds2[2];
    pthread_attr_t serverattrs;

    socketpair(PF_LOCAL, SOCK_STREAM, 0, fds1);
    socketpair(PF_LOCAL, SOCK_STREAM, 0, fds2);
    pthread_attr_init(&serverattrs);
    pthread_attr_setdetachstate(&serverattrs, 1);
    struct serverdata* serverdata;
    serverdata = malloc(sizeof(struct serverdata));
    serverdata->rdfd = fds2[1];
    serverdata->wrfd = fds1[1];
    serverdata->nthreads = serverthreads;
    pthread_create(&serverthread, &serverattrs, serverroutine, serverdata);
    myclient(fds1[0], fds2[0]);
    return 0;
}
#endif

#if (!defined(NOMODE) && MODE < 3)
int
connectdummy(void)
{
    mydirectclient();
    return 0;
}
#endif

static void
connectcommand(char* argv0full)
{
    int fds1[2];
    int fds2[2];
    pid_t pid;
    char* args[25];
    int argscnt = 0;

    args[argscnt++] = "/usr/bin/ssh";
    //args[argscnt++] = "-T";
    //args[argscnt++] = "-c";
    //args[argscnt++] = "aes128-ctr";
    //args[argscnt++] = "-x";
    //args[argscnt++] = "-o";
    //args[argscnt++] = "Compression=no";
    args[argscnt++] = "berry@fire";
    args[argscnt++] = "/home/berry/server";
    args[argscnt++] = NULL;

    socketpair(PF_LOCAL, SOCK_STREAM, 0, fds1);
    socketpair(PF_LOCAL, SOCK_STREAM, 0, fds2);
    pid = fork();     
    if (pid == 0) {
        close(fds1[0]);
        close(fds2[0]);
        dup2(fds1[1], 0);
        dup2(fds2[1], 1);
        close(fds1[1]);
        close(fds2[1]);
        execvp(args[0], args);
        fprintf(stderr,"Failed %s (%d)\n",strerror(errno),errno);
        abort();
    } else {
        close(fds1[1]);
        close(fds2[1]);
        myclient(fds2[0], fds1[0]);
    }
}

void
connectremote(char* argv0full)
{
    int fds1[2];
    int fds2[2];
    pid_t pid;
    char* args[2];

    args[0] = "server";
    args[1] = NULL;

    socketpair(PF_LOCAL, SOCK_STREAM, 0, fds1);
    socketpair(PF_LOCAL, SOCK_STREAM, 0, fds2);
    pid = fork();     
    if (pid == 0) {
        close(fds1[0]);
        close(fds2[0]);
        dup2(fds1[1], 0);
        dup2(fds2[1], 1);
        close(fds1[1]);
        close(fds2[1]);
        execvp(argv0full, args);
        abort();
    } else {
        close(fds1[1]);
        close(fds2[1]);
        myclient(fds2[0], fds1[0]);
    }
}

#define CHECKSYS(OP) do { int CHECK_status; if((CHECK_status=(OP)) != 0) { int CHECK_errno = errno; \
  fprintf(stderr,"operation %s on %s:%d failed: %d %s (%d)\n",#OP,__FILE__,__LINE__,CHECK_status,strerror(CHECK_errno),CHECK_errno); abort(); } } while(0)

void
serverlistenfifo(void)
{
    int sfd, cfd;
    socklen_t addrsize;
    struct sockaddr_un myaddr, peeraddr;
    sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&myaddr, 0, sizeof (myaddr));
    myaddr.sun_family = AF_UNIX;
    strncpy(myaddr.sun_path, "/tmp/server.sock", sizeof (myaddr.sun_path)-1);
    CHECKSYS(bind(sfd, (struct sockaddr *)&myaddr, sizeof (myaddr)));
    assert(listen(sfd, 5)==0);
    addrsize = sizeof (peeraddr);
    cfd = accept(sfd, (struct sockaddr *)&peeraddr, &addrsize);
    assert(cfd>=0);
    //close(sfd);
    dup2(cfd, 0);
    dup2(cfd, 1);
    //close(cfd);
}

void
serverlistensocket(void)
{
    int sfd, cfd;
    socklen_t addrsize;
    struct sockaddr_in myaddr, peeraddr;
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(7777);
    int optval = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval));
    CHECKSYS(bind(sfd, (struct sockaddr *)&myaddr, sizeof (myaddr)));
    assert(listen(sfd, 5)==0);
    addrsize = sizeof (peeraddr);
    cfd = accept(sfd, (struct sockaddr *)&peeraddr, &addrsize);
    assert(cfd>=0);
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof (optval));
    //close(sfd);
    dup2(cfd, 0);
    dup2(cfd, 1);
    //close(cfd);
}

void
connectfifo(void)
{
    int fd;
    socklen_t addrsize;
    int optval = 1;
    int optlen = sizeof (optval);
    struct sockaddr_un addr;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof (addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/server.sock", sizeof (addr.sun_path)-1);
    assert(connect(fd, (struct sockaddr *)&addr, sizeof (addr))==0);
    myclient(fd, fd);
}

void
connectsocket(void)
{
    int fd;
    socklen_t addrsize;
    int optval = 1;
    int optlen = sizeof (optval);
    struct sockaddr_in addr;
    struct hostent* h;
    h = gethostbyname("fire.halderen.net");
    assert(h);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd>0);
    addr.sin_family = AF_INET;
    addr.sin_addr = *((struct in_addr *)h->h_addr);
    addr.sin_port = htons(7777);
    //assert(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) == 0);
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof (optval));
    assert(connect(fd, (struct sockaddr *)&addr, sizeof (addr))==0);
    myclient(fd, fd);
}

static void*
test(void* data)
{
    int session;
    uint8_t buffer[4096];
    uint8_t hash[32];
    (void)data;

    pthread_barrier_wait(&barrier);
    ping();
    opensession(&session);
    randombytes(session, buffer, sizeof(buffer));
    for(int i=0; i<niters; i++) {
        sha256data(session, buffer, sizeof(buffer));
        sha256hash(session, hash);
    }
    closesession(session);
    return NULL;
}

/* MODE not defined, build separate client and server
 * MODE=0 direct call of application routines
 * MODE=1 indirect call without XDR routines
 * MODE=2 indirect call with XDR routines
 * MODE=3 internal running server
 * MODE=4 run as external running server with ssh channel
 * MODE=5 run as external running server externally started with unix fifo
 * MODE=6 run as external running server externally started with sockets
 */

extern char* argv0;
extern char* argv0path;
extern char* argv0full;

char* argv0;
char* argv0path;
char* argv0full;

int
programsetup(char* arg)
{
    int pos;
    argv0path = argv0full = NULL;
    for(int i=1; argv0path==NULL; i++) {
        argv0full = realloc(argv0path, i*PATH_MAX);
        if(!argv0full) {
            free(argv0path);
            goto fail;
        }
        argv0path = getcwd(argv0full, i*PATH_MAX);
        if(argv0path == NULL && errno != ERANGE) {
            free(argv0full);
            goto fail;
        }
    }
    if(arg[0] != '/') {
        int arglen = strlen(argv0path)+strlen(arg)+2;
        argv0full = realloc(argv0path, arglen);
        if(!argv0full) {
            free(argv0path);
            goto fail;
        }
        strncat(argv0full,"/",arglen);
        strncat(argv0full,arg,arglen);
    } else {
        int arglen = strlen(arg)+1;
        argv0full = malloc(arglen);
        strncpy(argv0full, arg, arglen);
    }
    pos = (strrchr(argv0full,'/') ? strrchr(argv0full,'/')-argv0full : 0);
    argv0path = malloc(pos + 1);
    if (!argv0path) {
        free(argv0full);
        goto fail;
    }
    strncpy(argv0path, argv0full, pos);
    argv0path[pos] = '\0';
    argv0 = &arg[pos+1];
    return 0;
  fail:
    argv0 = argv0path = argv0full = arg;
abort();
    return -1;
}

int
programteardown(void)
{
    if(argv0 == argv0path && argv0 == argv0full)
        return 0;
    free(argv0path);
    free(argv0full);
    return 0;
}

int
main(int argc, char* argv[])
{
    void* dummy;
    pthread_t* threads;

    programsetup(argv[0]);

#if (defined(MODE) && !defined(NOMODE))
#if (MODE == 1 || MODE == 2)
    connectdummy();
#elif (MODE == 3)
    connectinternal(4);
#endif
#if (MODE > 3)
    if(!strcmp(argv0, "server")) {
#if (MODE == 5)
        serverlistenfifo();
#elif (MODE == 6)
        serverlistensocket();
#endif
        myserver(0, 1, 32);
        exit(0);
    } else {
#if (MODE == 4)
        connectcommand(argv0path);
#elif (MODE == 5)
        connectfifo();
#elif (MODE == 6)
        connectsocket();
#endif
   }
#endif
#else
    connectcommand(argv0path);
#endif

    nthreads = (argc <= 1 ? 4 : atoi(argv[1]));
    threads = malloc(sizeof(pthread_t) * nthreads);
    niters = 24 * 1000 / nthreads;
    niters *= (argc <= 2 ? 16 : atoi(argv[2]));
    pthread_barrier_init(&barrier, NULL, nthreads+1);
    for(int i=0; i<nthreads; i++) {
        pthread_create(&threads[i], NULL, test, NULL);
    }
    pthread_barrier_wait(&barrier);
    for(int i=0; i<nthreads; i++) {
        pthread_join(threads[i], &dummy);
    }
    free(threads);
    myclose();
    programteardown();
    return 0;
}
