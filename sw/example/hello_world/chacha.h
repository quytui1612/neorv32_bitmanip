#ifndef CHACHA_H
#define CHACHA_H

/*
 * ChaCha20 Block Permutation — 512-bit ARX "block cipher".
 *
 * 20 rounds = 10 double-rounds. Each double-round = 8 quarter-rounds.
 * Each quarter-round has 4 ROL operations (by 16, 12, 8, 7).
 *
 * Total rotations per block: 80 QRs × 4 = 320 native 32-bit rori.
 * Plus: 320 modular additions + 320 xors = 960 total operations.
 *
 * Rotation density: 320/960 = 33%, but ABSOLUTE rotation count is massive.
 * Each rori without Zbb = srli+slli+or (3 instructions + stalls).
 * Savings: 320 × ~7 cycles = ~2240 cycles eliminated per block.
 *
 * Reference: Bernstein, "ChaCha, a variant of Salsa20" (2008).
 */

#include <stdint.h>

/* One ChaCha20 permutation (20 rounds) on 512-bit state.
 * in/out: 16 × 32-bit words = 64 bytes. */
void chacha20_block(uint32_t out[16], const uint32_t in[16]);

/* Benchmark wrappers (16-byte key signature compatibility) */
void chacha_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#endif /* CHACHA_H */
