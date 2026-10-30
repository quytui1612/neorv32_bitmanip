/*
 * SIMON-64/128 — 3 rotations/round, 44 rounds, 132 rotations/block.
 *
 * Round function (THE bitmanip hot path):
 *   f(x) = (ROL(x,1) & ROL(x,8)) ^ ROL(x,2) ^ k
 *   x_new = f(x) ^ y;  y = x;  x = x_new
 *
 * Dependency chain per round (sequential, no ILP):
 *   ROL1 = rotl32(x, 1)   → GCC+Zbb: rori x, 31
 *   ROL8 = rotl32(x, 8)   → GCC+Zbb: rori x, 24
 *   AND  = ROL1 & ROL8
 *   ROL2 = rotl32(x, 2)   → GCC+Zbb: rori x, 30
 *   T    = AND ^ ROL2
 *   OUT  = T ^ y ^ k
 *
 * Without Zbb: each ROL = srli + slli + or (3 instructions + stalls)
 * With Zbb:    each ROL = rori (1 instruction)
 *
 * 3 rotations × 44 rounds = 132 rori (BM) vs 396 shift instructions (base)
 * Difference: 264 extra instructions + pipeline stalls on serial chain
 */

#include <stdint.h>
#include <string.h>
#include "simon.h"

static inline uint32_t rotl32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32u - n));
}

/* Simon round function: f(x) = (ROL1(x) & ROL8(x)) ^ ROL2(x) */
static inline uint32_t simon_f(uint32_t x) {
    return (rotl32(x, 1) & rotl32(x, 8)) ^ rotl32(x, 2);
}

/* Key schedule for SIMON-64/128 */
void simon_init(simon_ctx_t *ctx, const uint8_t key[16]) {
    for (int i = 0; i < 4; i++) memcpy(&ctx->rk[i], key + 4 * i, 4);
    uint64_t z = UINT64_C(0xfc2ce51207a635db);
    for (int i = 4; i < 44; i++) {
        uint32_t a = ctx->rk[i - 1];
        uint32_t b = ctx->rk[i - 3];
        ctx->rk[i] = 0xfffffffcu ^ (uint32_t)(z & 1u) ^ ctx->rk[i - 4]
                   ^ ((a >> 3) | (a << 29)) ^ b
                   ^ ((a >> 4) | (a << 28)) ^ ((b >> 1) | (b << 31));
        z >>= 1;
    }
}

/* SIMON encrypt — fully unrolled for maximum bitmanip ratio */
void simon_encrypt(const simon_ctx_t *ctx, const uint8_t in[8], uint8_t out[8]) {
    uint32_t x, y;
    memcpy(&y, in,     4);
    memcpy(&x, in + 4, 4);

    /* 44 rounds fully unrolled — each has 3 rotations + AND + XORs */
    /* GCC with Zbb: 3 rori per round = 132 rori total */
    /* GCC without: 3 × (srli+slli+or) = 396 shift instructions total */

    #define ROUND(i) \
        y ^= simon_f(x) ^ ctx->rk[i]; \
        { uint32_t t = x; x = y; y = t; }

    ROUND( 0); ROUND( 1); ROUND( 2); ROUND( 3); ROUND( 4);
    ROUND( 5); ROUND( 6); ROUND( 7); ROUND( 8); ROUND( 9);
    ROUND(10); ROUND(11); ROUND(12); ROUND(13); ROUND(14);
    ROUND(15); ROUND(16); ROUND(17); ROUND(18); ROUND(19);
    ROUND(20); ROUND(21); ROUND(22); ROUND(23); ROUND(24);
    ROUND(25); ROUND(26); ROUND(27); ROUND(28); ROUND(29);
    ROUND(30); ROUND(31); ROUND(32); ROUND(33); ROUND(34);
    ROUND(35); ROUND(36); ROUND(37); ROUND(38); ROUND(39);
    ROUND(40); ROUND(41); ROUND(42); ROUND(43);

    #undef ROUND

    memcpy(out,     &y, 4);
    memcpy(out + 4, &x, 4);
}

/* Benchmark wrappers */
static simon_ctx_t g_simon_ctx;
static uint8_t g_simon_key[16];
static int g_simon_rdy = 0;

void simon_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    simon_ctx_t ctx;
    simon_init(&ctx, key);
    simon_encrypt(&ctx, in, out);
    memcpy(out + 8, out, 8);
}

void simon_bench_encrypt_only(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    if (!g_simon_rdy || memcmp(key, g_simon_key, 16)) {
        simon_init(&g_simon_ctx, key);
        memcpy(g_simon_key, key, 16);
        g_simon_rdy = 1;
    }
    simon_encrypt(&g_simon_ctx, in, out);
    memcpy(out + 8, out, 8);
}
