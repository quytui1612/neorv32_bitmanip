#ifndef MKV_TTABLE_H
#define MKV_TTABLE_H

/*
 * MKV-128 T-Table Implementation — Maximum Bitmanip Acceleration.
 *
 * Strategy: Precompute SubCells + MixWords into 4 lookup tables (T-tables).
 * Each F() round becomes just 4 table lookups + 3 XOR + 3 rori per column.
 *
 * Bitmanip instructions used (all in hot path):
 *   Zbb rori  — column rotation by k*8 bits (3 per column, 12 per F call)
 *   Zba sh2add — uint32_t table indexing (4 per column, 16 per F call)
 *
 * Without bitmanip:
 *   rori  → srli + slli + or = 3 instructions (×12 = 36 extra per F)
 *   sh2add → slli 2 + add = 2 instructions (×16 = 16 extra per F)
 *   Total penalty: ~52 extra instructions per F() call
 *
 * With 35 F() calls per block (7 encrypt + 28 key schedule):
 *   ~1820 extra instructions without bitmanip → significant slowdown
 *
 * GF polynomial: f(x) = x^8 + x^5 + x^3 + x + 1, reduction byte = 0x2B
 * Matrix M:
 *   { 0x01, 0x02, 0x01, 0x03 }
 *   { 0x03, 0x07, 0x01, 0x04 }
 *   { 0x04, 0x0B, 0x03, 0x0D }
 *   { 0x0D, 0x1E, 0x06, 0x14 }
 */

#include <stdint.h>
#include "mkv_wp.h"  /* reuse mkv_wp_ctx_t, MKV_ROUNDS_* */

/* Initialize T-tables. Must be called ONCE before any encrypt. */
void mkv_ttable_init(void);

/*
 * Encrypt one 16-byte block using T-tables.
 * Requires mkv_ttable_init() already called.
 * ctx must be pre-initialized via mkv_wp_init().
 */
void mkv_ttable_encrypt(const mkv_wp_ctx_t *ctx,
                        const uint8_t in[16], uint8_t out[16]);

/*
 * F() round function using T-tables.
 * Combines AddRoundKey + SubCells + MixWords + AddRoundKey + SubCells + XWords.
 * This is the bitmanip-critical hot path.
 */
void mkv_ttable_f128(uint32_t col[4], const uint32_t *k1, const uint32_t *k2);

/*
 * Key schedule using T-table F() function.
 * Produces same round keys as mkv_wp_init.
 */
void mkv_ttable_keysched(mkv_wp_ctx_t *ctx, int rounds, const uint8_t *masterKey);

/*
 * Benchmark wrapper: full key schedule + encrypt per call.
 */
void mkv_ttable_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#endif /* MKV_TTABLE_H */
