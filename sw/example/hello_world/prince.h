#ifndef PRINCE_H
#define PRINCE_H
#include <stdint.h>
typedef struct { uint64_t k0, k1, k0_prime; } prince_ctx_t;
void prince_init(prince_ctx_t *ctx, const uint8_t key[16]);
void prince_encrypt(const prince_ctx_t *ctx, const uint8_t in[8], uint8_t out[8]);
void prince_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void prince_bench_encrypt_only(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
#endif
