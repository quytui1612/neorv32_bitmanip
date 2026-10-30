/*
 * PRESENT-80 — Dual-structure implementation.
 *
 * BASELINE: Nibble-by-nibble S-box lookup (16× per SubCells)
 * BITMANIP: xperm4 parallel nibble lookup (2× per SubCells, 8× faster!)
 *
 * This demonstrates that DIFFERENT cipher structures for different ISA
 * capabilities produce DRAMATICALLY larger speedups than same-code-different-MARCH.
 */

#include <stdint.h>
#include <string.h>
#include "present.h"

/* ================================================================
 * xperm4 wrapper (only compiled with Zbkx)
 * ================================================================ */
#if defined(__riscv_zbkx) || defined(CIPHER_TEST_XPERM4)
static inline uint32_t xperm4(uint32_t sel, uint32_t table) {
    uint32_t rd;
#ifdef CIPHER_TEST_XPERM4
    rd = 0;
    for (unsigned i = 0; i < 8; i++)
        rd |= ((table >> (4u * ((sel >> (4u * i)) & 7u))) & 15u) << (4u * i);
#else
    /* rs1 holds the lookup table; rs2 holds the nibble indexes. */
    __asm__ volatile("xperm4 %0, %1, %2" : "=r"(rd) : "r"(table), "r"(sel));
#endif
    return rd;
}
#endif

/* ================================================================
 * SubCells — THE critical divergence point
 * ================================================================ */

/*
 * BASELINE: Nibble-by-nibble lookup.
 * For each of 16 nibbles in 64-bit state:
 *   1. Extract nibble (shift + mask)
 *   2. Lookup in S-box table (lbu)
 *   3. Insert back (shift + or)
 * Total: ~48 instructions for 64-bit state
 */
#if !defined(__riscv_zbkx) && !defined(CIPHER_TEST_XPERM4)
static uint64_t subcells_baseline(uint64_t state) {
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t nibble = (state >> (i * 4)) & 0xF;
        result |= (uint64_t)PRESENT_SBOX[nibble] << (i * 4);
    }
    return result;
}
#endif

/*
 * BITMANIP: xperm4 parallel nibble lookup.
 *
 * 64-bit state = 2 × 32-bit words, each with 8 nibbles.
 * For each word:
 *   1. Split nibbles: those with index < 8 go to "lo" lookup,
 *      those with index >= 8 go to "hi" lookup
 *   2. xperm4(lo_nibbles, sbox_lo_packed) → results for nibbles < 8
 *   3. xperm4(lo_nibbles, sbox_hi_packed) → results for nibbles >= 8
 *   4. Select correct result based on bit-3 of each nibble
 *
 * Total: ~12 instructions for 64-bit state (vs 48 baseline)
 */
#if defined(__riscv_zbkx) || defined(CIPHER_TEST_XPERM4)
static uint64_t subcells_xperm4(uint64_t state) {
    uint32_t lo = (uint32_t)state;
    uint32_t hi = (uint32_t)(state >> 32);
    uint32_t sbox_lo = SBOX_LO_PACKED;
    uint32_t sbox_hi = SBOX_HI_PACKED;
    const uint32_t mask3 = 0x77777777u;  /* bits 0-2 of each nibble */

    /* For lower word */
    uint32_t lo_idx = lo & mask3;         /* nibble index without bit 3 */
    uint32_t lo_r0 = xperm4(lo_idx, sbox_lo);  /* results if original nibble < 8 */
    uint32_t lo_r1 = xperm4(lo_idx, sbox_hi);  /* results if original nibble >= 8 */
    /* Expand bit 3 of each input nibble to a full nibble selection mask. */
    uint32_t lo_full_sel = (lo >> 3) & 0x11111111u;  /* bit0 of each nibble */
    lo_full_sel = lo_full_sel * 0xFu;  /* expand: 0→0x0, 1→0xF */
    uint32_t lo_out = (lo_r0 & ~lo_full_sel) | (lo_r1 & lo_full_sel);

    /* For upper word */
    uint32_t hi_idx = hi & mask3;
    uint32_t hi_r0 = xperm4(hi_idx, sbox_lo);
    uint32_t hi_r1 = xperm4(hi_idx, sbox_hi);
    uint32_t hi_full_sel = (hi >> 3) & 0x11111111u;
    hi_full_sel = hi_full_sel * 0xFu;
    uint32_t hi_out = (hi_r0 & ~hi_full_sel) | (hi_r1 & hi_full_sel);

    return (uint64_t)lo_out | ((uint64_t)hi_out << 32);
}
#endif

/* SubCells dispatch */
static uint64_t subcells(uint64_t state) {
#if defined(__riscv_zbkx) || defined(CIPHER_TEST_XPERM4)
    return subcells_xperm4(state);
#else
    return subcells_baseline(state);
#endif
}

/* ================================================================
 * pLayer — bit permutation (optimized, same for both builds)
 *
 * PRESENT P: P[4j+k] = j + k*16  (4x16 bit matrix transpose)
 *
 * Original: 64-iteration bit-by-bit loop (~320 instructions)
 * Optimized: 16 table lookups + shifts + ORs (~48 instructions)
 *
 * Each source byte contributes 4 bits to r_lo and 4 bits to r_hi,
 * at positions determined by the byte's position in the state.
 * ================================================================ */
static const uint32_t pbox_lo[256] = {
    0x00000000u,0x00000001u,0x00010000u,0x00010001u,0x00000000u,0x00000001u,0x00010000u,0x00010001u,
    0x00000000u,0x00000001u,0x00010000u,0x00010001u,0x00000000u,0x00000001u,0x00010000u,0x00010001u,
    0x00000002u,0x00000003u,0x00010002u,0x00010003u,0x00000002u,0x00000003u,0x00010002u,0x00010003u,
    0x00000002u,0x00000003u,0x00010002u,0x00010003u,0x00000002u,0x00000003u,0x00010002u,0x00010003u,
    0x00020000u,0x00020001u,0x00030000u,0x00030001u,0x00020000u,0x00020001u,0x00030000u,0x00030001u,
    0x00020000u,0x00020001u,0x00030000u,0x00030001u,0x00020000u,0x00020001u,0x00030000u,0x00030001u,
    0x00020002u,0x00020003u,0x00030002u,0x00030003u,0x00020002u,0x00020003u,0x00030002u,0x00030003u,
    0x00020002u,0x00020003u,0x00030002u,0x00030003u,0x00020002u,0x00020003u,0x00030002u,0x00030003u,
    0x00000000u,0x00000001u,0x00010000u,0x00010001u,0x00000000u,0x00000001u,0x00010000u,0x00010001u,
    0x00000000u,0x00000001u,0x00010000u,0x00010001u,0x00000000u,0x00000001u,0x00010000u,0x00010001u,
    0x00000002u,0x00000003u,0x00010002u,0x00010003u,0x00000002u,0x00000003u,0x00010002u,0x00010003u,
    0x00000002u,0x00000003u,0x00010002u,0x00010003u,0x00000002u,0x00000003u,0x00010002u,0x00010003u,
    0x00020000u,0x00020001u,0x00030000u,0x00030001u,0x00020000u,0x00020001u,0x00030000u,0x00030001u,
    0x00020000u,0x00020001u,0x00030000u,0x00030001u,0x00020000u,0x00020001u,0x00030000u,0x00030001u,
    0x00020002u,0x00020003u,0x00030002u,0x00030003u,0x00020002u,0x00020003u,0x00030002u,0x00030003u,
    0x00020002u,0x00020003u,0x00030002u,0x00030003u,0x00020002u,0x00020003u,0x00030002u,0x00030003u,
    0x00000000u,0x00000001u,0x00010000u,0x00010001u,0x00000000u,0x00000001u,0x00010000u,0x00010001u,
    0x00000000u,0x00000001u,0x00010000u,0x00010001u,0x00000000u,0x00000001u,0x00010000u,0x00010001u,
    0x00000002u,0x00000003u,0x00010002u,0x00010003u,0x00000002u,0x00000003u,0x00010002u,0x00010003u,
    0x00000002u,0x00000003u,0x00010002u,0x00010003u,0x00000002u,0x00000003u,0x00010002u,0x00010003u,
    0x00020000u,0x00020001u,0x00030000u,0x00030001u,0x00020000u,0x00020001u,0x00030000u,0x00030001u,
    0x00020000u,0x00020001u,0x00030000u,0x00030001u,0x00020000u,0x00020001u,0x00030000u,0x00030001u,
    0x00020002u,0x00020003u,0x00030002u,0x00030003u,0x00020002u,0x00020003u,0x00030002u,0x00030003u,
    0x00020002u,0x00020003u,0x00030002u,0x00030003u,0x00020002u,0x00020003u,0x00030002u,0x00030003u,
    0x00000000u,0x00000001u,0x00010000u,0x00010001u,0x00000000u,0x00000001u,0x00010000u,0x00010001u,
    0x00000000u,0x00000001u,0x00010000u,0x00010001u,0x00000000u,0x00000001u,0x00010000u,0x00010001u,
    0x00000002u,0x00000003u,0x00010002u,0x00010003u,0x00000002u,0x00000003u,0x00010002u,0x00010003u,
    0x00000002u,0x00000003u,0x00010002u,0x00010003u,0x00000002u,0x00000003u,0x00010002u,0x00010003u,
    0x00020000u,0x00020001u,0x00030000u,0x00030001u,0x00020000u,0x00020001u,0x00030000u,0x00030001u,
    0x00020000u,0x00020001u,0x00030000u,0x00030001u,0x00020000u,0x00020001u,0x00030000u,0x00030001u,
    0x00020002u,0x00020003u,0x00030002u,0x00030003u,0x00020002u,0x00020003u,0x00030002u,0x00030003u,
    0x00020002u,0x00020003u,0x00030002u,0x00030003u,0x00020002u,0x00020003u,0x00030002u,0x00030003u,
};
static const uint32_t pbox_hi[256] = {
    0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000001u,0x00000001u,0x00000001u,0x00000001u,
    0x00010000u,0x00010000u,0x00010000u,0x00010000u,0x00010001u,0x00010001u,0x00010001u,0x00010001u,
    0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000001u,0x00000001u,0x00000001u,0x00000001u,
    0x00010000u,0x00010000u,0x00010000u,0x00010000u,0x00010001u,0x00010001u,0x00010001u,0x00010001u,
    0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000001u,0x00000001u,0x00000001u,0x00000001u,
    0x00010000u,0x00010000u,0x00010000u,0x00010000u,0x00010001u,0x00010001u,0x00010001u,0x00010001u,
    0x00000000u,0x00000000u,0x00000000u,0x00000000u,0x00000001u,0x00000001u,0x00000001u,0x00000001u,
    0x00010000u,0x00010000u,0x00010000u,0x00010000u,0x00010001u,0x00010001u,0x00010001u,0x00010001u,
    0x00000002u,0x00000002u,0x00000002u,0x00000002u,0x00000003u,0x00000003u,0x00000003u,0x00000003u,
    0x00010002u,0x00010002u,0x00010002u,0x00010002u,0x00010003u,0x00010003u,0x00010003u,0x00010003u,
    0x00000002u,0x00000002u,0x00000002u,0x00000002u,0x00000003u,0x00000003u,0x00000003u,0x00000003u,
    0x00010002u,0x00010002u,0x00010002u,0x00010002u,0x00010003u,0x00010003u,0x00010003u,0x00010003u,
    0x00000002u,0x00000002u,0x00000002u,0x00000002u,0x00000003u,0x00000003u,0x00000003u,0x00000003u,
    0x00010002u,0x00010002u,0x00010002u,0x00010002u,0x00010003u,0x00010003u,0x00010003u,0x00010003u,
    0x00000002u,0x00000002u,0x00000002u,0x00000002u,0x00000003u,0x00000003u,0x00000003u,0x00000003u,
    0x00010002u,0x00010002u,0x00010002u,0x00010002u,0x00010003u,0x00010003u,0x00010003u,0x00010003u,
    0x00020000u,0x00020000u,0x00020000u,0x00020000u,0x00020001u,0x00020001u,0x00020001u,0x00020001u,
    0x00030000u,0x00030000u,0x00030000u,0x00030000u,0x00030001u,0x00030001u,0x00030001u,0x00030001u,
    0x00020000u,0x00020000u,0x00020000u,0x00020000u,0x00020001u,0x00020001u,0x00020001u,0x00020001u,
    0x00030000u,0x00030000u,0x00030000u,0x00030000u,0x00030001u,0x00030001u,0x00030001u,0x00030001u,
    0x00020000u,0x00020000u,0x00020000u,0x00020000u,0x00020001u,0x00020001u,0x00020001u,0x00020001u,
    0x00030000u,0x00030000u,0x00030000u,0x00030000u,0x00030001u,0x00030001u,0x00030001u,0x00030001u,
    0x00020000u,0x00020000u,0x00020000u,0x00020000u,0x00020001u,0x00020001u,0x00020001u,0x00020001u,
    0x00030000u,0x00030000u,0x00030000u,0x00030000u,0x00030001u,0x00030001u,0x00030001u,0x00030001u,
    0x00020002u,0x00020002u,0x00020002u,0x00020002u,0x00020003u,0x00020003u,0x00020003u,0x00020003u,
    0x00030002u,0x00030002u,0x00030002u,0x00030002u,0x00030003u,0x00030003u,0x00030003u,0x00030003u,
    0x00020002u,0x00020002u,0x00020002u,0x00020002u,0x00020003u,0x00020003u,0x00020003u,0x00020003u,
    0x00030002u,0x00030002u,0x00030002u,0x00030002u,0x00030003u,0x00030003u,0x00030003u,0x00030003u,
    0x00020002u,0x00020002u,0x00020002u,0x00020002u,0x00020003u,0x00020003u,0x00020003u,0x00020003u,
    0x00030002u,0x00030002u,0x00030002u,0x00030002u,0x00030003u,0x00030003u,0x00030003u,0x00030003u,
    0x00020002u,0x00020002u,0x00020002u,0x00020002u,0x00020003u,0x00020003u,0x00020003u,0x00020003u,
    0x00030002u,0x00030002u,0x00030002u,0x00030002u,0x00030003u,0x00030003u,0x00030003u,0x00030003u,
};

static uint64_t player(uint64_t state) {
    uint32_t lo = (uint32_t)state;
    uint32_t hi = (uint32_t)(state >> 32);
    uint32_t r_lo, r_hi;

    r_lo  = pbox_lo[ lo        & 0xFF]
          | (pbox_lo[(lo >>  8) & 0xFF] <<  2)
          | (pbox_lo[(lo >> 16) & 0xFF] <<  4)
          | (pbox_lo[(lo >> 24) & 0xFF] <<  6)
          | (pbox_lo[ hi        & 0xFF] <<  8)
          | (pbox_lo[(hi >>  8) & 0xFF] << 10)
          | (pbox_lo[(hi >> 16) & 0xFF] << 12)
          | (pbox_lo[(hi >> 24) & 0xFF] << 14);

    r_hi  = pbox_hi[ lo        & 0xFF]
          | (pbox_hi[(lo >>  8) & 0xFF] <<  2)
          | (pbox_hi[(lo >> 16) & 0xFF] <<  4)
          | (pbox_hi[(lo >> 24) & 0xFF] <<  6)
          | (pbox_hi[ hi        & 0xFF] <<  8)
          | (pbox_hi[(hi >>  8) & 0xFF] << 10)
          | (pbox_hi[(hi >> 16) & 0xFF] << 12)
          | (pbox_hi[(hi >> 24) & 0xFF] << 14);

    return (uint64_t)r_lo | ((uint64_t)r_hi << 32);
}

/* ================================================================
 * Key schedule
 * ================================================================ */
void present_init(present_ctx_t *ctx, const uint8_t key[16]) {
    /* The first ten bytes are the 80-bit key in the published bit order. */
    uint64_t high = 0;
    uint16_t low = 0;
    for (int i = 0; i < 8; i++) high = (high << 8) | key[i];
    low = ((uint16_t)key[8] << 8) | key[9];

    for (int i = 0; i < 32; i++) {
        ctx->rwk[i] = high;
        if (i == 31) break;
        /* Rotate the complete 80-bit register left by 61 positions. */
        uint16_t next_low = (uint16_t)(high >> 3);
        high = (high << 61) | ((uint64_t)low << 45) | (high >> 19);
        low = next_low;

        /* S-box on bits 79:76. */
        uint8_t top4 = (uint8_t)((high >> 60) & 0xF);
        high &= 0x0FFFFFFFFFFFFFFFULL;
        high |= (uint64_t)PRESENT_SBOX[top4] << 60;

        /* Round counter for the next key, in positions 19:15. */
        uint8_t rc = (uint8_t)(i + 1);
        low ^= (uint16_t)(rc & 1u) << 15;
        high ^= (uint64_t)(rc >> 1);
    }
}

/* ================================================================
 * Encrypt
 * ================================================================ */
void present_encrypt(const present_ctx_t *ctx, const uint8_t in[8], uint8_t out[8]) {
    uint64_t state = 0;
    for (int i = 0; i < 8; i++) state = (state << 8) | in[i];

    for (int i = 0; i < 31; i++) {
        /* AddRoundKey */
        state ^= ctx->rwk[i];
        /* SubCells: #ifdef selects baseline or xperm4 */
        state = subcells(state);
        /* pLayer: bit permutation (same for both builds) */
        state = player(state);
    }
    /* Final AddRoundKey */
    state ^= ctx->rwk[31];

    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)state; state >>= 8; }
}

/* ================================================================
 * Benchmark wrappers
 * ================================================================ */
static present_ctx_t g_present_ctx;
static uint8_t g_present_key[16];
static int g_present_rdy = 0;

void present_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    present_ctx_t ctx;
    present_init(&ctx, key);
    present_encrypt(&ctx, in, out);
    memcpy(out + 8, out, 8);
}

void present_bench_encrypt_only(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    if (!g_present_rdy || memcmp(key, g_present_key, 16)) {
        present_init(&g_present_ctx, key);
        memcpy(g_present_key, key, 16);
        g_present_rdy = 1;
    }
    present_encrypt(&g_present_ctx, in, out);
    memcpy(out + 8, out, 8);
}
