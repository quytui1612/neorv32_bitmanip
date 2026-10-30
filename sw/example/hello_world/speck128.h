#ifndef SPECK128_H
#define SPECK128_H

/*
 * SPECK-128/128 — 64-bit word ARX cipher on RV32.
 *
 * Block: 128-bit (2×64-bit), Key: 128-bit, Rounds: 32.
 *
 * The 64-bit rotations cross 32-bit word boundaries on RV32, so the
 * implementation uses shifts and ORs on both halves of each 64-bit word.
 */

#include <stdint.h>

/* 64-bit word as two 32-bit halves (little-endian: lo = bits 31:0) */
typedef struct { uint32_t lo, hi; } u64_t;

typedef struct { u64_t rk[32]; } speck128_ctx_t;

void speck128_init(speck128_ctx_t *ctx, const uint8_t key[16]);
void speck128_encrypt(const speck128_ctx_t *ctx, const uint8_t in[16], uint8_t out[16]);

void speck128_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void speck128_bench_encrypt_only(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#endif /* SPECK128_H */
