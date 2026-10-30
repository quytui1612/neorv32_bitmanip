#ifndef SIMON_H
#define SIMON_H

/*
 * SIMON-64/128 — ARX cipher with HIGHEST rotation density.
 *
 * Block: 64-bit (2×32-bit Feistel), Key: 128-bit, Rounds: 44.
 *
 * Round function:
 *   x_new = (ROL(x,1) & ROL(x,8)) ^ ROL(x,2) ^ y ^ k[i]
 *
 * 3 rotations per round × 44 rounds = 132 rori instructions.
 * Plus: 1 AND + 2 XOR + 1 key XOR = tight serial dependency chain.
 *
 * Rotation density: 3/7 = 43% (vs Speck 2/5 = 40%)
 *
 * The AND gate (ROL1 & ROL8) creates a 3-deep dependency chain:
 *   rori → rori → and → rori → xor → xor → xor
 * Without Zbb, each rori = srli+slli+or (3 instructions),
 * making the chain 9 instructions longer → MORE pipeline stalls.
 *
 * SIMON vs SPECK comparison:
 *   Speck: 54 rot,  27 rnd, density 40%, speedup +26%
 *   SIMON: 132 rot, 44 rnd, density 43%, expected +30%+
 */

#include <stdint.h>

typedef struct { uint32_t rk[44]; } simon_ctx_t;

void simon_init(simon_ctx_t *ctx, const uint8_t key[16]);
void simon_encrypt(const simon_ctx_t *ctx, const uint8_t in[8], uint8_t out[8]);

/* Benchmark wrappers */
void simon_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void simon_bench_encrypt_only(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#endif /* SIMON_H */
