#ifndef SPECK_H
#define SPECK_H

/*
 * SPECK-64/128 block cipher
 * 64-bit block (2×32-bit words), 128-bit key (4×32-bit words), 27 rounds.
 *
 * Why SPECK for demonstrating Zbb (rori)?
 * ----------------------------------------
 * SPECK is a pure ARX cipher: Add + Rotate + XOR, NO S-box tables.
 * Each encryption round uses exactly 2 rotations:
 *   x = (ROR32(x, 8) + y) ^ k[i]
 *   y = (ROL32(y, 3)) ^ x
 *
 * 27 rounds × 2 rotations = 54 rori per block encrypt.
 * Rotations ≈ 40% of total work (remainder: 27 ADD + 27 XOR per half-word).
 *
 * Without Zbb: each rotation = srli + slli + or + pipeline stalls ≈ 48 cyc
 * With    Zbb: each rotation = rori                               ≈ 22 cyc
 *
 * Expected speedup from Zbb: ~1.5× (vs ~1.1× for AES word-parallel)
 *
 * References: Beaulieu et al., "The SIMON and SPECK Families of Lightweight
 *             Block Ciphers", NSA Cryptology Report 2013.
 */

#include <stdint.h>

/* Precomputed key schedule: 27 round keys (one 32-bit word each) */
typedef struct { uint32_t rk[27]; } speck_ctx_t;

/* Key expansion */
void speck_init(speck_ctx_t *ctx, const uint8_t key[16]);

/* Encrypt one 64-bit block (in/out as two 32-bit halves, little-endian) */
void speck_encrypt(const speck_ctx_t *ctx,
                   const uint8_t in[8],
                         uint8_t out[8]);

/* Single-block wrapper matching the generic benchmark signature */
void speck_encrypt_block(const uint8_t key[16],
                         const uint8_t in[16],
                               uint8_t out[16]);

/* Decrypt one 64-bit block */
void speck_decrypt(const speck_ctx_t *ctx,
                   const uint8_t in[8],
                         uint8_t out[8]);

#endif /* SPECK_H */
