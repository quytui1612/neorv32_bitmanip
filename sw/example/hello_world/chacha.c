/*
 * ChaCha20 Block Permutation — 320 native 32-bit rotations per block.
 *
 * Each quarter-round (QR):
 *   a += b; d ^= a; d = ROL(d, 16);   ← 1 add, 1 xor, 1 ROL
 *   c += d; b ^= c; b = ROL(b, 12);   ← 1 add, 1 xor, 1 ROL
 *   a += b; d ^= a; d = ROL(d,  8);   ← 1 add, 1 xor, 1 ROL
 *   c += d; b ^= c; b = ROL(b,  7);   ← 1 add, 1 xor, 1 ROL
 *
 * 20 rounds = 10 double-rounds.
 * Per double-round: 8 QRs (4 column + 4 diagonal).
 * Total: 80 QRs × 4 ROL = 320 rotations.
 *
 * GCC+Zbb: ROL(x,n) → rori rd, rs, (32-n)   (1 instruction)
 * Without: srli + slli + or                   (3 instructions + stalls)
 */

#include <stdint.h>
#include <string.h>
#include "chacha.h"

static inline uint32_t rotl32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32u - n));
}

/* Quarter-round macro — 4 rotations per call */
#define QR(a, b, c, d) \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d,  8); \
    c += d; b ^= c; b = rotl32(b,  7)

void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x0, x1, x2,  x3,  x4,  x5,  x6,  x7,
             x8, x9, x10, x11, x12, x13, x14, x15;

    x0 = in[0];  x1 = in[1];  x2 = in[2];  x3 = in[3];
    x4 = in[4];  x5 = in[5];  x6 = in[6];  x7 = in[7];
    x8 = in[8];  x9 = in[9];  x10 = in[10]; x11 = in[11];
    x12 = in[12]; x13 = in[13]; x14 = in[14]; x15 = in[15];

    for (int i = 0; i < 10; i++) {
        /* Column rounds — 4 QRs = 16 rotations */
        QR(x0, x4, x8,  x12);
        QR(x1, x5, x9,  x13);
        QR(x2, x6, x10, x14);
        QR(x3, x7, x11, x15);
        /* Diagonal rounds — 4 QRs = 16 rotations */
        QR(x0, x5, x10, x15);
        QR(x1, x6, x11, x12);
        QR(x2, x7, x8,  x13);
        QR(x3, x4, x9,  x14);
    }

    out[0]  = x0  + in[0];  out[1]  = x1  + in[1];
    out[2]  = x2  + in[2];  out[3]  = x3  + in[3];
    out[4]  = x4  + in[4];  out[5]  = x5  + in[5];
    out[6]  = x6  + in[6];  out[7]  = x7  + in[7];
    out[8]  = x8  + in[8];  out[9]  = x9  + in[9];
    out[10] = x10 + in[10]; out[11] = x11 + in[11];
    out[12] = x12 + in[12]; out[13] = x13 + in[13];
    out[14] = x14 + in[14]; out[15] = x15 + in[15];
}

/* Benchmark: 512-bit block permutation, reported as 128-bit equivalent */
void chacha_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    /* Build 512-bit state from key+in pattern */
    static uint32_t state[16];
    static uint32_t result[16];
    int i;

    /* Initialize state (deterministic from key+in) */
    for (i = 0; i < 4; i++) memcpy(&state[i], &key[i*4], 4);
    for (i = 4; i < 8; i++) memcpy(&state[i], &in[(i-4)*4 % 16], 4);
    /* Constants */
    state[8]  = 0x61707865; state[9]  = 0x3320646e;
    state[10] = 0x79622d32; state[11] = 0x6b206574;
    /* Counter + nonce from in */
    for (i = 12; i < 16; i++) memcpy(&state[i], &in[(i-12)*4 % 16], 4);

    chacha20_block(result, state);

    /* Output first 16 bytes */
    memcpy(out, result, 16);
}
