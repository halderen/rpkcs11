#ifndef SHA256_H
#define SHA256_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

struct sha256_context {
	unsigned char data[64];
	uint32_t  datalen;
	uint64_t bitlen;
	uint32_t state[8];
};

void sha256_init(struct sha256_context* ctx);
void sha256_update(struct sha256_context* ctx, const uint8_t* data, uint32_t len);
void sha256_final(struct sha256_context* ctx, uint8_t hash[32]);

#ifdef __cplusplus
}
#endif

#endif
