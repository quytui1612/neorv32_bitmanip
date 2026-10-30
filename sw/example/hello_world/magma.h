#ifndef MAGMA_H
#define MAGMA_H

/*
 * Magma (GOST R 34.12-2015 / GOST 28147-89) — Bitmanip demonstration.
 *
 * Block: 64-bit (2×32-bit Feistel), Key: 256-bit (8×32-bit subkeys).
 * 32 rounds: f(x) = ROL11( S_composite(x + k_i) )
 *
 * Two implementations to demonstrate Bitmanip benefit:
 *
 * [A] magma_encrypt_prerot  — PRE-ROTATED tables
 *     The ROL11 is absorbed into the lookup tables at build time.
 *     No rotation instruction ever executed. Zbb gives ZERO benefit.
 *     4 × 256 × 4 = 4 KB of lookup tables in IMEM (.rodata).
 *     Bottleneck: 4 × 256-entry table loads per round × 32 rounds = 128 loads.
 *
 * [B] magma_encrypt_rori    — NATURAL tables + explicit ROL11
 *     Tables store S-box output in natural bit positions (no rotation).
 *     ROL11 applied explicitly after each table lookup set.
 *     With Zbb:    rori rd, rs, 21          = 1 instruction
 *     Without Zbb: srli+slli+or+stalls      ≈ 48 cycles
 *     Savings:     32 rounds × (48-22) ≈ 832 cycles/block  → ~1.2-1.3×
 *
 * Why xperm4 (Zbkx) does NOT help Magma:
 *     xperm4 does: for each nibble position i → look up nibble[i] in table rs1
 *     Works when SAME table applies to ALL 8 nibble positions.
 *     Magma uses 8 DIFFERENT 4-bit S-boxes (one per nibble position) →
 *     need a different xperm4 call per position = no parallelism gain vs lw.
 *     (xperm4 is ideal for DES/PRESENT which use 1-2 S-boxes, not 8 different.)
 *
 * Zbkb rev8 benefit (minor):
 *     GETU32_BE currently = 4 shift + 3 OR = 7 instr → rev8 = lw+rev8 = 2 instr.
 *     Used 2× per block → saves ~50 cycles. Small but real.
 *
 * Total Bitmanip speedup for Magma: ~1.2-1.3× (much clearer than AES ~1.1×)
 * because Magma has explicit rotation every round unlike AES.
 */

#include <stdint.h>

/* Context: 8 subkeys (256-bit key, loaded once) */
typedef struct { uint32_t k[8]; } magma_ctx_t;

/*
 * Initialize context from 32-byte key.
 * Also initializes the natural (un-rotated) lookup tables — call once.
 */
void magma_init(magma_ctx_t *ctx, const uint8_t key[32]);

/* [A] Pre-rotated tables: ROL11 absorbed, no rori in hot path */
void magma_encrypt_prerot(const magma_ctx_t *ctx,
                          const uint8_t in[8],
                                uint8_t out[8]);

/* [B] Natural tables + explicit ROL11: rori in hot path */
void magma_encrypt_rori(const magma_ctx_t *ctx,
                        const uint8_t in[8],
                              uint8_t out[8]);

/* Decrypt (uses pre-rotated tables) */
void magma_decrypt_prerot(const magma_ctx_t *ctx,
                          const uint8_t in[8],
                                uint8_t out[8]);

/* Generic benchmark wrappers matching run_benchmark() signature */
void magma_bench_prerot(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void magma_bench_rori  (const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#endif /* MAGMA_H */
