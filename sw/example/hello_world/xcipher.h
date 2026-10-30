#ifndef XCIPHER_H
#define XCIPHER_H
#include <stdint.h>
typedef struct { uint64_t rk[17]; } xc_ctx_t;
void xc_init(xc_ctx_t *ctx, const uint8_t key[16]);
void xc_encrypt(const xc_ctx_t *ctx, const uint8_t in[8], uint8_t out[8]);
void xc_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void xc_bench_encrypt_only(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
#endif
