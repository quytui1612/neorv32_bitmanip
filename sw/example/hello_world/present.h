#ifndef PRESENT_H
#define PRESENT_H

/*
 * PRESENT-80 — Lightweight Block Cipher (ISO/IEC 29192-2).
 *
 * Block: 64-bit, Key: 80-bit, Rounds: 31.
 * SubCells: 16 parallel 4-bit S-box lookups.
 *
 * TWO completely different structures via #ifdef:
 *
 * BASELINE (no Zbkx):
 *   SubCells: 16× (nibble extract + table lookup + nibble insert)
 *   = ~64 instructions per SubCells call
 *
 * BITMANIP (Zbkx xperm4):
 *   SubCells: 2× xperm4 (parallel nibble lookup)
 *   = ~8 instructions per SubCells call
 *   → 8× fewer instructions for SubCells!
 *
 * xperm4 rd, rs1, rs2:
 *   rs1 is the packed 8-nibble table and rs2 contains the indexes.
 *   For each nibble i: rd[i] = rs1[rs2[i]].
 *
 * Since S-box has 16 entries but xperm4 table has only 8 nibbles:
 *   - Split into sbox_lo[0..7] and sbox_hi[8..15]
 *   - For nibbles with index < 8: xperm4(sbox_lo, state_clr_msb)
 *   - For nibbles with index >= 8: xperm4(sbox_hi, state_clr_msb)
 *   - Merge using bit-3 mask as selector
 */

#include <stdint.h>

/* PRESENT S-box (4-bit → 4-bit) */
static const uint8_t PRESENT_SBOX[16] = {
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};

/* Pack S-box into two 32-bit registers for xperm4 */
#define SBOX_LO_PACKED ( \
    ((uint32_t)PRESENT_SBOX[0]      ) | \
    ((uint32_t)PRESENT_SBOX[1] <<  4) | \
    ((uint32_t)PRESENT_SBOX[2] <<  8) | \
    ((uint32_t)PRESENT_SBOX[3] << 12) | \
    ((uint32_t)PRESENT_SBOX[4] << 16) | \
    ((uint32_t)PRESENT_SBOX[5] << 20) | \
    ((uint32_t)PRESENT_SBOX[6] << 24) | \
    ((uint32_t)PRESENT_SBOX[7] << 28)   \
)
#define SBOX_HI_PACKED ( \
    ((uint32_t)PRESENT_SBOX[ 8]      ) | \
    ((uint32_t)PRESENT_SBOX[ 9] <<  4) | \
    ((uint32_t)PRESENT_SBOX[10] <<  8) | \
    ((uint32_t)PRESENT_SBOX[11] << 12) | \
    ((uint32_t)PRESENT_SBOX[12] << 16) | \
    ((uint32_t)PRESENT_SBOX[13] << 20) | \
    ((uint32_t)PRESENT_SBOX[14] << 24) | \
    ((uint32_t)PRESENT_SBOX[15] << 28)   \
)

/* PRESENT bit permutation table */
static const uint8_t PRESENT_P[64] = {
     0, 16, 32, 48,  1, 17, 33, 49,  2, 18, 34, 50,  3, 19, 35, 51,
     4, 20, 36, 52,  5, 21, 37, 53,  6, 22, 38, 54,  7, 23, 39, 55,
     8, 24, 40, 56,  9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};

typedef struct {
    uint64_t rwk[32];  /* 31 round keys + 1 final, 64-bit each */
} present_ctx_t;

void present_init(present_ctx_t *ctx, const uint8_t key[16]);
void present_encrypt(const present_ctx_t *ctx, const uint8_t in[8], uint8_t out[8]);

void present_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void present_bench_encrypt_only(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#endif /* PRESENT_H */
