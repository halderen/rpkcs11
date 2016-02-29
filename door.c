#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <malloc.h>
#include <pthread.h>
#include <rpc/rpc.h>
#include "doorrpc.h"

static pthread_key_t buffer_key;

struct callstack {
    int size;
    int index;
    unsigned char buffer;
};

struct callstack *
getcallstack(void)
{
    struct callstack* callstack = pthread_getspecific(buffer_key);
    if (callstack == NULL) {
        callstack = malloc(sizeof (struct callstack) + sizeof (unsigned char) * 10240);
        callstack->index = 0;
        callstack->size = 0;
        pthread_setspecific(buffer_key, callstack);
    }
    return callstack;
}

void
door_setcallbuffer(struct callstack *callstack)
{
    pthread_setspecific(buffer_key, callstack);
}

void
door_initialize(void)
{
    pthread_key_create(&buffer_key, free);
}
        
void
door_arg_get(struct callstack* callstack, void* ptr)
{
    size_t size;
    callstack->index += sizeof (void*);
    memcpy(&size, &(&callstack->buffer)[callstack->index], sizeof (size_t));
    callstack->index += sizeof (void*);
    memcpy(ptr, &(&callstack->buffer)[callstack->index], size);
    callstack->index += size;
}

void
door_arg_ref(struct callstack* callstack, void** ptr, size_t *size)
{
    callstack->index += sizeof (void*);
    memcpy(size, &(&callstack->buffer)[callstack->index], sizeof (size_t));
    callstack->index += sizeof (void*);
    memcpy(*ptr, &(&callstack->buffer)[callstack->index], *size);
    callstack->index += *size;
}

void*
door_arg_basic()
{
    struct callstack* callstack = getcallstack();
    void* ptr;
    size_t size;
    callstack->index += sizeof (void*);
    memcpy(&size, &(&callstack->buffer)[callstack->index], sizeof (size_t));
    callstack->index += sizeof (size_t);
    ptr = &(&callstack->buffer)[callstack->index];
    callstack->index += size;
    return ptr;
}

int
door_arg_pass(void* ptr, size_t size)
{
    struct callstack* callstack = getcallstack();
    memcpy(&(&callstack->buffer)[callstack->index], &ptr, sizeof(void*));
    callstack->index += sizeof(void*);
    memcpy(&(&callstack->buffer)[callstack->index], &size, sizeof(size_t));
    callstack->index += sizeof(size_t);
    memcpy(&(&callstack->buffer)[callstack->index], ptr, size);
    callstack->index += size;
    return 1;
}

int
door_arg_passcount(void* ptr, unsigned long count, size_t size)
{
    struct callstack* callstack = getcallstack();
    door_arg_pass(&count, sizeof(int));
    if(ptr == NULL) {
        door_arg_pass(&ptr, 0);
    } else {
        door_arg_pass(ptr, size*count);
    }
    return 1;
}

int
door_arg_passcount2(void* ptr, unsigned long* count, size_t size)
{
    struct callstack* callstack = getcallstack();
    door_arg_pass(&count, sizeof(int));
    if(ptr == NULL) {
        door_arg_pass(&ptr, 0);
    } else {
        door_arg_pass(ptr, size*(*count));
    }
    return 1;
}

void
door_arg_passback(struct callstack* callstack)
{
    void* ptr;
    size_t size;
    assert(callstack->index == 0);
    while(callstack->index < callstack->size) {
        memcpy(&ptr, &(&callstack->buffer)[callstack->index], sizeof (void*));
        callstack->index += sizeof (void*);
        memcpy(&size, &(&callstack->buffer)[callstack->index], sizeof (size_t));
        callstack->index += sizeof (size_t);
        memcpy(ptr, &(&callstack->buffer)[callstack->index], size);
        callstack->index += size;
    }
    callstack->index = 0;
    callstack->size  = 0;
}

void
door_return(struct callstack* callstack)
{
    callstack->index = 0;
}

void
door_getcallbuffer(char** buffer, unsigned int* size)
{
    struct callstack* callstack = getcallstack();
    callstack->size  = callstack->index;
    callstack->index = 0;
    *size = sizeof(struct callstack) + callstack->size - sizeof(unsigned char);
    *buffer = (void*)callstack;
}
