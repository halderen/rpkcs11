#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <dlfcn.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include "pkcs11.h"
#include "server.h"

static void* dlhandle;
CK_FUNCTION_LIST_PTR local = NULL;

extern void pkcsprog_1(struct svc_req *rqstp, register SVCXPRT *transp);

static int reportfd = -1;

static int
setupreport(void)
{
    int len;
    char* filename;
    len = snprintf(NULL, 0, "%s/log/%s", STATEDIR, PACKAGE);
    filename = malloc(len+1);
    sprintf(filename, "%s/log/%s", STATEDIR, PACKAGE);
    reportfd = open(filename, O_APPEND|O_CREAT, 0666);
    free(filename);
    return 0;
}

int
report(char* fmt, ...)
{
    va_list ap;
    int len;
    char* str;
    va_start(ap, fmt);
    if(reportfd < 0)
        setupreport();
    len = vsnprintf(NULL, 0, fmt, ap);
    str = malloc(len+1);
    vsnprintf(str, 0, fmt, ap);
    write(reportfd, str, len);
    va_end(ap);
    return 0;
}

static int
tunnel(int fd)
{
    int err;
    char buffer[32768];
    ssize_t len;
    int timeout = 24 * 60 * 60 * 1000;
    for(;;) {
        struct pollfd fds[2];
        fds[0].fd = 0;
        fds[0].events = POLLIN|POLLHUP;
        fds[0].revents = 0;
        fds[1].fd = fd;
        fds[1].events = POLLIN|POLLHUP;
        fds[1].revents = 0;
        if((err = poll(fds, 2, timeout)) <= 0) {
            report("timeout %s (%d)\n",strerror(err),err);
            break;
        }
        if((fds[0].revents & POLLHUP)) {
            report("termination of external connection\n");
            break;
        }
        if((fds[1].revents & POLLHUP)) {
            report("termination of internal connection\n");
            break;
        }
        if((fds[0].revents & POLLIN)) {
            len = read(fds[0].fd, buffer, sizeof (buffer));
            write(fd, buffer, len);
        }
        if((fds[1].revents & POLLIN)) {
            len = read(fds[1].fd, buffer, sizeof (buffer));
            write(1, buffer, len);
        }
    }

    return 0;
}

static int
openmodule(char* library)
{
    CK_RV status;
    CK_C_GetFunctionList getFunctionList;
    dlhandle = dlopen(library, RTLD_LAZY);
    assert(dlhandle);
    getFunctionList = dlsym(dlhandle, "C_GetFunctionList");
    assert(getFunctionList);
    status = getFunctionList(&local);
    assert(!status);
    assert(local);
    return 0;
}

static int
rpcservice(void)
{
    register SVCXPRT *transp;
    pmap_unset(PKCSPROG, PKCSVERS);
    if ((transp = svcudp_create(RPC_ANYSOCK)) == NULL) {
        return 1;
    }
    if (!svc_register(transp, PKCSPROG, PKCSVERS, pkcsprog_1, IPPROTO_UDP)) {
        return 2;
    }
    if ((transp = svctcp_create(RPC_ANYSOCK, 0, 0)) == NULL) {
        return 3;
    }
    if (!svc_register(transp, PKCSPROG, PKCSVERS, pkcsprog_1, IPPROTO_UDP)) {
        return 4;
    }
    svc_run();
    return 0;
}

static int
tunnelservice(int fd)
{
    register SVCXPRT *transp;

    if((transp = svcfd_create(fd, 0, 0))==NULL) {
        return 1;
    }
    svc_register(transp, PKCSPROG, PKCSVERS, pkcsprog_1, IPPROTO_NONE);
    svc_run();    

    return 0;
}

int
main(int argc, char* argv[])
{
    int fd[2];
    pid_t parent, pid;

    if (PKCS11_HOST && strlen(PKCS11_HOST)>0) {
        socketpair(PF_LOCAL, SOCK_STREAM, 0, fd);
        parent = getpid();
        pid = fork();
        if(pid==0) {
            close(0);
            close(1);
            sleep(3);
            close(fd[0]);
            openmodule(PKCS11_MODULE);
            tunnelservice(fd[1]);
            close(fd[1]);
            kill(parent, SIGTERM);
        } else {
            close(fd[1]);
            tunnel(fd[0]);
            kill(pid, SIGTERM);
            waitpid(pid, NULL, 0);
        }
    } else {
        openmodule(PKCS11_MODULE);
        rpcservice();
    }

    exit(0);
}
