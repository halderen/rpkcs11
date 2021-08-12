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
 * 
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
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/random.h>
#include "myapplication.h"
#include "sha256.h"

struct session {
    int id;
    struct sha256_context sha256_context;
};

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#define maxsessions 64
static int numsessions = 0;
static struct session sessions[maxsessions];

#if (MODE>0 && !defined(NOMODE))
#define ping ping_impl
#define getproperties getproperties_impl
#define opensession opensession_impl
#define closesession closesession_impl
#define randombytes randombytes_impl
#define sha256data sha256data_impl
#define sha256hash sha256hash_impl
#endif

void
ping(void)
{
    return;
}

int
getproperties(int nproperties, struct property* properties)
{
    if(nproperties >= 3) {
        properties[0].name  = strdup("version");
        properties[0].value = strdup("1.0");
        properties[1].name  = strdup("author");
        properties[1].value = strdup("Berry van Halderen");
        properties[2].name  = strdup("manufacturer");
        properties[2].value = strdup("NLnet Labs");
    }
    return 3;
}

static struct session*
getsession(int id)
{
    for(int i=0; i<numsessions && i<maxsessions; i++) {
        if(sessions[i].id == id)
            return &sessions[i];
    }
    return NULL;
}

int
opensession(int* id)
{
    struct session* session = NULL;
    pthread_mutex_lock(&mutex);
    if (numsessions < maxsessions) {
        session = &sessions[numsessions];
    } else {
        for(int i=0; i<maxsessions; i++)
            if(sessions[i].id == -1) {
                session = &sessions[i];
                break;
            }
        if(session == NULL)
            return -1;
    }
    session->id = numsessions++;
    pthread_mutex_unlock(&mutex);
    sha256_init(&(sessions[numsessions].sha256_context));
    *id = session->id;
    return 0;
}

int
closesession(int id)
{
    struct session* session = getsession(id);
    if(session == NULL)
        return -1;
    pthread_mutex_lock(&mutex);
    session->id = -1;
    pthread_mutex_unlock(&mutex);
    return 0;
}

void
randombytes(int id, uint8_t *buffer, int length)
{
    struct session* session = getsession(id);
    if(session == NULL)
        return;
    getrandom(buffer, length, GRND_RANDOM);
}

void
sha256data(int id, uint8_t* buffer, int length)
{
    struct session* session = getsession(id);
    if(session == NULL)
        return;
    sha256_update(&session->sha256_context, buffer, length);
}

void
sha256hash(int id, uint8_t hash[32])
{
    struct session* session = getsession(id);
    if(session == NULL)
        return;
    sha256_final(&session->sha256_context, hash);
}