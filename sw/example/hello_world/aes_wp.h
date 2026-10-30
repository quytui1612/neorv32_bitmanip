#ifndef AES_WP_H
#define AES_WP_H

/*
 * Word-Parallel AES-128 ECB — designed to benefit from RISC-V Zbb (Bitmanip).
 *
 * Difference vs tiny-AES-c (LUT-based, byte-oriented):
 *
 *   tiny-AES-c:  state[col][row] as uint8_t[4][4]
 *                MixColumns  → 4 bytes × 4 col × 9 rounds = looping over bytes
 *                ShiftRows   → byte swaps
 *
 *   This impl:   state[col] as uint32_t[4]  (1 col = 1 word = 4 bytes packed)
 *                MixColumns  →  t   = xtime_word(w)          // word-level GF(2^8) ×2
 *                               r   = t ^ w                  // w[i] × 3
 *                               res = t ^ ror(r,8)           // 2·a0 ^ 3·a1 ^ a2 ^ a3
 *                                     ^ ror(w,16)            // per-byte via rotation
 *                                     ^ ror(w,24)
 *                               → 3 ror per column
 *
 * Zbb benefit (measured at compile-time via -march=...zbb...):
 *
 *   Operation                  Without Zbb              With Zbb
 *   ror32(x, n)                srl + sll + or = 3 insn  rori = 1 insn  (saves 2)
 *   x & ~0x80808080            lui + not + and = 3 insn  andn = 1 insn  (saves 2)
 *
 *   MixColumns:  3 ror × 4 col × 9 rounds = 108 ror  → saves 216 instructions/block
 *   xtime_word:  1 andn × 4 col × 10 rounds = 40 andn → saves  40 instructions/block
 *
 * Total expected saving: ~256 instructions/block ≈ 10–20% faster than rv32imc baseline.
 *
 * The sbox array is still used for SubBytes (16 byte-lookups per round) — this part
 * is memory-bound and Zbb cannot help here, so the speedup is partial.
 */

#include <stdint.h>

/*
 * Encrypt one 16-byte block with AES-128 ECB using word-parallel implementation.
 * Same correct output as tiny-AES-c (verified against NIST SP 800-38A).
 */
void aes128_ecb_encrypt_wp(const uint8_t key[16],
                            const uint8_t in[16],
                            uint8_t out[16]);

/*
 * Encrypt-only: uses pre-expanded round keys (from AES_init_ctx).
 * rk must point to 44 uint32_t (= AES_ctx.RoundKey cast to uint32_t*).
 */
void aes128_ecb_encrypt_wp_rk(const uint32_t *rk,
                               const uint8_t in[16],
                               uint8_t out[16]);

/*
 * Zba variant: identical to aes128_ecb_encrypt_wp() but SubBytes uses a
 * uint32_t S-box (wp_sbox_w32) so GCC+Zba emits 'sh2add' for each index.
 * Saves 160 address-scale instructions per block vs [2] without Zba.
 */
void aes128_ecb_encrypt_wp_zba(const uint8_t key[16],
                                const uint8_t in[16],
                                uint8_t out[16]);

#endif /* AES_WP_H */
