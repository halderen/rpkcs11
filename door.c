#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <malloc.h>
#include <pthread.h>
#include <rpc/rpc.h>
#include "doorrpc.h"
#include "door.h"

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
    if(size == 0)
        ptr = NULL;
    else
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
door_arg_passvalue(void* ptr, size_t size)
{
    void* nullptr = NULL;
    struct callstack* callstack = getcallstack();
    memcpy(&(&callstack->buffer)[callstack->index], &nullptr, sizeof(void*));
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
    door_arg_passvalue(&count, sizeof(unsigned long));
    if(ptr == NULL) {
        door_arg_pass(NULL, 0);
    } else {
        door_arg_pass(ptr, size*count);
    }
    return 1;
}

int
door_arg_passstatic(void* ptr, unsigned long count, size_t size)
{
    struct callstack* callstack = getcallstack();
    door_arg_passvalue(&count, sizeof(unsigned long));
    if(ptr == NULL) {
        door_arg_passvalue(NULL, 0);
    } else {
        door_arg_passvalue(ptr, size*count);
    }
    return 1;
}

int
door_arg_passcount2(void* ptr, unsigned long maxcount, unsigned long* actualcount, size_t size)
{
    door_arg_passvalue(&maxcount, sizeof(unsigned long));
    door_arg_pass(actualcount, sizeof(unsigned long));
    if(ptr == NULL) {
        door_arg_pass(&ptr, 0);
    } else {
        door_arg_pass(ptr, size*(maxcount));
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
        if(ptr != NULL) {

            memcpy(ptr, &(&callstack->buffer)[callstack->index], size);
        }
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

void
door_verify(void)
{
    struct callstack* callstack = getcallstack();
    assert(callstack->size == callstack->index);
}

void
door_marshall_complexarray(void *ptr, long unsigned count, size_t size, int ptr_offset, int len_offset)
{
    int i;
    char* item;
    void* itemdata;
    unsigned long* itemdatalen;
    door_arg_passstatic(ptr, count, size);
    for(i=0; i<count; i++) {
        item = &((char*)ptr)[size*i];
        itemdata = *(unsigned char**)&(item[ptr_offset]);
        itemdatalen = (unsigned long*)&(item[len_offset]);
        door_arg_passcount2(itemdata, *itemdatalen, itemdatalen, 1);
    }
}

void
door_unmarshall_complexarray(void *ptrptr, long unsigned *count, size_t size, int ptr_offset, int len_offset)
{
    unsigned char** ptr = ptrptr;
    void** dest;
    int i;
    unsigned long maxcount, *actualcount;
    *count = door_GET(unsigned long);
    *ptr = door_OBJ(void*);
    for(i=0; i<*count; i++) {
        maxcount = door_GET(unsigned long);
        (void)maxcount;
        actualcount = door_OBJ(unsigned long *);
        (void)actualcount;
        dest = (void**) &((*ptr)[size*i+ptr_offset]);
        *dest = door_OBJ(unsigned char*);
    }
}
