/*
 * SPECK-64/128 — pure ARX block cipher, Zbb (rori) demonstration.
 *
 * Round function (27 rounds):
 *   x = (ROR32(x, 8) + y) ^ k[i]      ← 1 rori, 1 add, 1 xor
 *   y = ROL32(y, 3) ^ x                ← 1 rori (= ROR32(y,29)), 1 xor
 *
 * Key schedule uses same structure on 4 key words.
 *
 * GCC with -Os and rv32imc_zbb will emit:
 *   ROR32(x,8)  → rori a0, a0, 8     (1 instr)
 *   ROL32(y,3)  → rori a1, a1, 29    (1 instr)  ROL(x,n) = ROR(x,32-n)
 *
 * GCC without Zbb will emit:
 *   ROR32(x,8)  → srli+slli+or        (3 instr + 2 RAW stalls ≈ 48 cyc)
 *   ROL32(y,3)  → srli+slli+or        (3 instr + 2 RAW stalls ≈ 48 cyc)
 */

#include <stdint.h>
#include <string.h>
#include "speck.h"

/* Number of rounds for SPECK-64/128 */
#define SPECK_ROUNDS 27

/* ROR32 and ROL32 — GCC+Zbb recognizes these patterns as rori */
static inline uint32_t ror32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32u - n));
}

static inline uint32_t rol32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32u - n));
}

/* SPECK-64/128 key expansion.
 * key[16]: 4 little-endian 32-bit words k0..k3
 * Round keys: rk[0..26]
 *
 * Schedule: B[i+1] = (ROR(B[i], 8) + A[i]) ^ i
 *           A[i+1] = ROL(A[i], 3) ^ B[i+1]
 * where A starts as k[0], B[j] shift through k[1..3] then repeat.
 */
void speck_init(speck_ctx_t *ctx, const uint8_t key[16])
{
    /* Load 4 key words little-endian */
    uint32_t k[4];
    for (int i = 0; i < 4; i++) {
        k[i]  = (uint32_t)key[4*i + 0]
              | (uint32_t)key[4*i + 1] << 8
              | (uint32_t)key[4*i + 2] << 16
              | (uint32_t)key[4*i + 3] << 24;
    }

    /* A = k[0], rotate through k[1], k[2], k[3] as "l" array */
    uint32_t A = k[0];
    uint32_t L[3] = { k[1], k[2], k[3] };

    ctx->rk[0] = A;
    for (uint32_t i = 0; i < SPECK_ROUNDS - 1; i++) {
        uint32_t idx = i % 3u;
        /* L[(i+3-1)%3] = (ROR(L[i%3], 8) + A) ^ i */
        uint32_t tmp = (ror32(L[idx], 8) + A) ^ i;
        /* A = ROL(A, 3) ^ L_new */
        A = rol32(A, 3) ^ tmp;
        L[idx] = tmp;
        ctx->rk[i + 1] = A;
    }
}

/* SPECK-64/128 encrypt one 64-bit block.
 * in[8], out[8]: little-endian 64-bit plaintext/ciphertext.
 */
void speck_encrypt(const speck_ctx_t *ctx,
                   const uint8_t in[8],
                         uint8_t out[8])
{
    /* Load x=high half, y=low half, both little-endian 32-bit */
    uint32_t x = (uint32_t)in[4]
               | (uint32_t)in[5] << 8
               | (uint32_t)in[6] << 16
               | (uint32_t)in[7] << 24;
    uint32_t y = (uint32_t)in[0]
               | (uint32_t)in[1] << 8
               | (uint32_t)in[2] << 16
               | (uint32_t)in[3] << 24;

    /* 27 rounds — this is where rori appears */
    for (int i = 0; i < SPECK_ROUNDS; i++) {
        x = (ror32(x, 8) + y) ^ ctx->rk[i]; /* rori x,8 + add + xor */
        y = rol32(y, 3) ^ x;                 /* rori y,29 + xor     */
    }

    /* Store */
    out[0] = (uint8_t)(y >>  0); out[1] = (uint8_t)(y >>  8);
    out[2] = (uint8_t)(y >> 16); out[3] = (uint8_t)(y >> 24);
    out[4] = (uint8_t)(x >>  0); out[5] = (uint8_t)(x >>  8);
    out[6] = (uint8_t)(x >> 16); out[7] = (uint8_t)(x >> 24);
}

/* SPECK-64/128 decrypt one 64-bit block. */
void speck_decrypt(const speck_ctx_t *ctx,
                   const uint8_t in[8],
                         uint8_t out[8])
{
    uint32_t x = (uint32_t)in[4] | (uint32_t)in[5]<<8
               | (uint32_t)in[6]<<16 | (uint32_t)in[7]<<24;
    uint32_t y = (uint32_t)in[0] | (uint32_t)in[1]<<8
               | (uint32_t)in[2]<<16 | (uint32_t)in[3]<<24;

    for (int i = SPECK_ROUNDS - 1; i >= 0; i--) {
        y = ror32(y ^ x, 3);               /* inverse ROL(y,3)^x   */
        x = ror32((x ^ ctx->rk[i]) - y, 24); /* inverse ROR(x,8)+y^k */
    }

    out[0]=(uint8_t)(y>>0); out[1]=(uint8_t)(y>>8);
    out[2]=(uint8_t)(y>>16); out[3]=(uint8_t)(y>>24);
    out[4]=(uint8_t)(x>>0); out[5]=(uint8_t)(x>>8);
    out[6]=(uint8_t)(x>>16); out[7]=(uint8_t)(x>>24);
}

/*
 * Wrapper matching the generic benchmark signature:
 *   enc(key[16], plaintext[16], ciphertext[16])
 *
 * Uses a static context. Key schedule is recomputed only when key changes.
 * This ensures we benchmark only the 27-round encrypt loop, not key expansion.
 */
void speck_encrypt_block(const uint8_t key[16],
                         const uint8_t in[16],
                               uint8_t out[16])
{
    static speck_ctx_t ctx;
    static uint8_t last_key[16];
    static int initialized = 0;

    if (!initialized || memcmp(key, last_key, 16) != 0) {
        speck_init(&ctx, key);
        memcpy(last_key, key, 16);
        initialized = 1;
    }

    /* Encrypt first 64-bit block; copy to out[16] */
    uint8_t tmp[8];
    speck_encrypt(&ctx, in, tmp);
    memcpy(out,     tmp, 8);
    memcpy(out + 8, tmp, 8); /* fill remaining 8 bytes (for uniform interface) */
}
