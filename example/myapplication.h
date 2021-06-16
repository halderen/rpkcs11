#ifndef MYAPPLICATION_H
#define MYAPPLICATION_H

#include <stdlib.h>
#include <stdint.h>

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
int myclient(int rdfd, int wrfd);

#endif
