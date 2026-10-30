#ifndef AES_TTABLE_H
#define AES_TTABLE_H

/*
 * AES-128 T-table implementation — maximum bitmanip optimization.
 *
 * Combines SubBytes + ShiftRows + MixColumns into table lookups.
 * Uses ONLY 1 T-table (1 KB) + rori (Zbb) for MixColumns rotation.
 * GCC+Zba auto-emits sh2add for uint32_t table indexing.
 *
 * Bitmanip instructions used (all in hot path):
 *   Zbb rori   — 3 per column × 4 cols × 9 rounds = 108 rori/block
 *   Zba sh2add — 4 per column × 4 cols × 9 rounds = 144 sh2add/block
 *
 * This code REQUIRES bitmanip — no baseline fallback.
 *
 * Table: Te[256] = 1 KB in .rodata (vs 4 KB for classic 4-table approach)
 * Final round uses S-box directly (no MixColumns).
 */

#include <stdint.h>

/* Initialize T-table. Must be called ONCE before encrypt. */
void aes_ttable_init(void);

/*
 * Encrypt one 16-byte block using T-tables.
 * rk must point to 44 uint32_t (from AES_init_ctx, cast to uint32_t*).
 * REQUIRES: aes_ttable_init() already called.
 */
void aes_ttable_encrypt_rk(const uint32_t *rk,
                            const uint8_t in[16],
                            uint8_t out[16]);

/*
 * Benchmark wrapper: cached key + encrypt.
 * Key expansion done once; only encrypt phase measured.
 */
void aes_ttable_bench(const uint8_t key[16],
                      const uint8_t in[16],
                      uint8_t out[16]);

#endif /* AES_TTABLE_H */
