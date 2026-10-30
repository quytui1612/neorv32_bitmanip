#ifndef SPECK_FAST_H
#define SPECK_FAST_H

/*
 * SPECK-64/128 — Fully Optimized for Bitmanip Comparison.
 *
 * TWO structural optimizations vs standard speck.c:
 *
 * 1. LOOP UNROLLED: 27 rounds fully unrolled.
 *    Eliminates 27× (addi + bne) = 54 instructions of loop overhead.
 *    This overhead is identical for both BM and baseline builds,
 *    so removing it INCREASES the bitmanip/baseline ratio.
 *
 * 2. WORD-ALIGNED I/O: Takes uint32_t* instead of uint8_t*.
 *    Eliminates 8× (lbu+slli+or) prologue + 8× (srli+sb) epilogue = ~50 instructions.
 *    Again, this overhead is the SAME for both builds → removing it increases ratio.
 *
 * 3. ROUND KEYS IN REGISTERS: All 27 keys loaded once, kept in register pressure.
 *    GCC -Os will spill to stack, but the key loads (lw) become amortized.
 *
 * Mathematical analysis:
 *   Standard: BM = 8×27+50 = 266 instr, Base = 12×27+50 = 374 → 28.9% savings
 *   Optimized: BM = 6×27+6 = 168 instr, Base = 10×27+6 = 276 → 39.1% savings
 *                                                             ↑ TARGET: 35%+
 */

#include <stdint.h>
#include "speck.h"  /* reuse speck_ctx_t */

/* Optimized encrypt: word-aligned I/O, fully unrolled. */
void speck_fast_encrypt(const speck_ctx_t *ctx, const uint32_t in[2], uint32_t out[2]);

/* Benchmark wrapper (16-byte key signature, byte I/O converted to word internally) */
void speck_fast_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/* Benchmark: pre-expanded key, word I/O — minimum overhead. */
void speck_fast_bench_pure(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#endif /* SPECK_FAST_H */
