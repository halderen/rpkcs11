#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
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

static void
connectcommand(char* argv0full)
{
    int fds1[2];
    int fds2[2];
    pid_t pid;
    char* args[4];

    args[0] = "/usr/bin/ssh";
    args[1] = "berry@trade";
    args[2] = "/home/berry/server";
    args[3] = NULL;

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
        execvp("/usr/bin/ssh", args);
        abort();
    } else {
        close(fds1[1]);
        close(fds2[1]);
        myclient(fds2[0], fds1[0]);
    }
}

static void
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
 * MODE=4 run as external running server
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
#if (MODE == 3)
    connectinternal(4);
#endif
#if (MODE > 3)
    if(!strcmp(argv0, "server")) {
        myserver(0, 1, 4);
        abort();
    } else {
        connectcommand(argv0path);
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
fprintf(stderr,"DONE\n");
    return 0;
}
