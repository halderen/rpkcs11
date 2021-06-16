#ifndef MYTRANSPORT_H
#define MYTRANSPORT_H

#include <rpc/xdr.h>
#include <rpc/types.h>
#include "myapplication.h"

struct getproperties_args {
    int16_t nproperties;
    struct property* properties;
};

struct randombytes_args {
    int16_t session;
    unsigned int length;
    uint8_t* bytes;
};

struct sha256data_args {
    int16_t session;
    unsigned int length;
    uint8_t* bytes;
};

struct sha256hash_args {
    int16_t session;
    uint8_t  bytes[32];
};

bool_t getproperties_xdr(XDR *xdrs, struct getproperties_args* args);
bool_t randombytes_xdr(XDR *xdrs, struct randombytes_args* args);
bool_t sha256data_xdr(XDR *xdrs, struct sha256data_args* args);
bool_t sha256hash_xdr(XDR *xdrs, struct sha256hash_args* args);

void ping_clnt();
int getproperties_clnt(int nproperties, struct property* properties);
int opensession_clnt(int* session);
int closesession_clnt(int session);
void randombytes_clnt(int session, uint8_t *buffer, int length);
void sha256data_clnt(int session, uint8_t* buffer, int length);
void sha256hash_clnt(int session, uint8_t hash[32]);

int ping_call(void* ptr);
int getproperties_call(struct getproperties_args* args);
int opensession_call(int* id);
int closesession_call(int* id);
void randombytes_call(struct randombytes_args* args);
void sha256data_call(struct sha256data_args* args);
void sha256hash_call(struct sha256hash_args* args);

#endif
