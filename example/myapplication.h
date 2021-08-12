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
#ifndef MYAPPLICATION_H
#define MYAPPLICATION_H

#include "config.h"
#include <stdlib.h>
#include <stdint.h>
#include "channelrpc.h"

struct property {
    char* name;
    char* value;
};

void ping();
int getproperties(int nproperties, struct property* properties);
int opensession(int* session);
int closesession(int session);
void randombytes(int session, uint8_t *buffer, int length);
void sha256data(int session, uint8_t* buffer, int length);
void sha256hash(int session, uint8_t hash[32]);

void ping_impl();
int getproperties_impl(int nproperties, struct property* properties);
int opensession_impl(int* session);
int closesession_impl(int session);
void randombytes_impl(int session, uint8_t *buffer, int length);
void sha256data_impl(int session, uint8_t* buffer, int length);
void sha256hash_impl(int session, uint8_t hash[32]);

int myserver(int rdfd, int wrfd, int nthreads);
int mydirectserver(struct channelrpc_client* clnt, int buffered);
int myclient(int rdfd, int wrfd);
int mydirectclient(void);
void myclose(void);

#endif
