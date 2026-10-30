#ifndef LEA_H
#define LEA_H

/*
 * LEA-128 — Lightweight Encryption Algorithm (KISA, KR).
 *
 * Block: 128-bit (4×32-bit words), Key: 128-bit, Rounds: 24.
 *
 * Pure ARX cipher (Add-Rotate-XOR), no S-box, no MUL.
 * Each round has 4 ROL operations → 96 rotations per block.
 *
 * This is the MAXIMUM bitmanip-benefiting cipher:
 *   Zbb rori: 96 rotations/block (ROL9=rori23, ROL5=rori27, ROL3=rori29)
 *   Without Zbb: each rotation = srli+slli+or = 3 instructions + pipeline stalls
 *   Savings: 96 × ~16 cycles = ~1500 cycles per block
 *
 * Reference: Hong et al., "LEA: A 128-Bit Block Cipher for Fast
 *            Encryption on Common Processors" (2014).
 */

#include <stdint.h>

typedef struct {
    uint32_t rk[96];  /* 24 rounds × 4 unique words; T1 is reused */
} lea_ctx_t;

/* Key expansion from 16-byte key */
void lea_init(lea_ctx_t *ctx, const uint8_t key[16]);

/* Encrypt one 128-bit block */
void lea_encrypt(const lea_ctx_t *ctx, const uint8_t in[16], uint8_t out[16]);

/* Benchmark: key schedule + encrypt (full cost) */
void lea_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/* Benchmark: encrypt only (pre-expanded key) */
void lea_bench_encrypt_only(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#endif /* LEA_H */
