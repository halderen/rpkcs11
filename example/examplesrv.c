#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include "myapplication.h"
#include "mytransport.h"

int
main(int argc, char* argv[])
{
    int nthreads;
    nthreads = (argc <= 1 ? 4 : atoi(argv[1]));
    myserver(0, 1, nthreads);
    return 0;
}
