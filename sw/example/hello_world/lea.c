/*
 * LEA-128 — Lightweight Encryption Algorithm.
 *
 * LEA-128 has 24 rounds. Each encryption round uses ROL9, ROR5 and ROR3;
 * the key schedule also rotates four 32-bit words per round.
 * Round keys are stored as four unique words; T[1] is reused three times.
 */

#include <stdint.h>
#include <string.h>
#include "lea.h"

/* ROL32 — THE critical bitmanip pattern.
 * GCC+Zbb: rori rd, rs, (32-n)   → 1 instruction (~2 cycles)
 * GCC base: srli+slli+or         → 3 instructions (~7+ cycles with stalls)
 */
static inline uint32_t rotl32(uint32_t x, unsigned n) {
    if (n == 0) return x;
    return (x << n) | (x >> (32u - n));
}

/* Delta constants for key schedule */
static const uint32_t DELTA[4] = {
    0xC3EFE9DBu, 0x44626B02u, 0x79E27C8Au, 0x78DF30ECu
};

void lea_init(lea_ctx_t *ctx, const uint8_t key[16]) {
    uint32_t T[4];
    /* Load key as 4 little-endian 32-bit words */
    memcpy(T, key, 16);

    for (int i = 0; i < 24; i++) {
        uint32_t d = DELTA[i & 3];
        /* Key schedule: four rotations of delta and four of the key words. */
        T[0] = rotl32(T[0] + rotl32(d, (unsigned)i % 32u), 1);
        T[1] = rotl32(T[1] + rotl32(d, (unsigned)(i + 1) % 32u), 3);
        T[2] = rotl32(T[2] + rotl32(d, (unsigned)(i + 2) % 32u), 6);
        T[3] = rotl32(T[3] + rotl32(d, (unsigned)(i + 3) % 32u), 11);
        ctx->rk[i*4  ] = T[0];
        ctx->rk[i*4+1] = T[1];
        ctx->rk[i*4+2] = T[2];
        ctx->rk[i*4+3] = T[3];
    }
}

void lea_encrypt(const lea_ctx_t *ctx, const uint8_t in[16], uint8_t out[16]) {
    uint32_t X0, X1, X2, X3;
    memcpy(&X0, in,      4);
    memcpy(&X1, in + 4,  4);
    memcpy(&X2, in + 8,  4);
    memcpy(&X3, in + 12, 4);

    for (int i = 0; i < 24; i++) {
        const uint32_t *rk = &ctx->rk[i * 4];
        uint32_t n0 = rotl32((X0 ^ rk[0]) + (X1 ^ rk[1]), 9);
        uint32_t n1 = rotl32((X1 ^ rk[2]) + (X2 ^ rk[1]), 27); /* ROR5 */
        uint32_t n2 = rotl32((X2 ^ rk[3]) + (X3 ^ rk[1]), 29); /* ROR3 */
        X3 = X0; X0 = n0; X1 = n1; X2 = n2;
    }

    memcpy(out,      &X0, 4);
    memcpy(out + 4,  &X1, 4);
    memcpy(out + 8,  &X2, 4);
    memcpy(out + 12, &X3, 4);
}

/* Benchmark: full key schedule + encrypt each call */
void lea_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    lea_ctx_t ctx;
    lea_init(&ctx, key);
    lea_encrypt(&ctx, in, out);
}

/* Benchmark: encrypt only with cached key */
void lea_bench_encrypt_only(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    static lea_ctx_t ctx;
    static uint8_t saved_key[16];
    static int ready = 0;
    if (!ready || memcmp(key, saved_key, 16)) {
        lea_init(&ctx, key);
        memcpy(saved_key, key, 16);
        ready = 1;
    }
    lea_encrypt(&ctx, in, out);
}
