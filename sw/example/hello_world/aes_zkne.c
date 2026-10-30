/*
 * AES-128 ECB encryption accelerated with RISC-V Zkne (scalar crypto) instructions.
 *
 * Algorithm overview
 * ------------------
 * The RV32 Zkne extension provides two instructions that each implement one
 * "byte lane" of an AES forward round:
 *
 *   aes32esmi rd, rs1, rs2, bs
 *       Extracts byte bs (0-3) from rs2, applies AES SubBytes, then computes
 *       the MixColumns contribution of that single byte, rotates the 32-bit
 *       result left by (bs*8) bits, and XORs it into rs1 → rd.
 *       Used for rounds 1–9 (SubBytes + ShiftRows + MixColumns combined).
 *
 *   aes32esi rd, rs1, rs2, bs
 *       Same but without MixColumns – just SubBytes + rotation + XOR.
 *       Used for the final round 10.
 *
 * State representation
 * --------------------
 * tiny-AES-c stores the 4×4 state as uint8_t[col][row] in memory:
 *   buf[0..3]  = column 0  (row 0 at lowest address)
 *   buf[4..7]  = column 1
 *   buf[8..11] = column 2
 *   buf[12..15]= column 3
 *
 * We pack each column into a uint32_t with row-r at bits [8r+7 : 8r]:
 *   s[c] = col_r0 | col_r1<<8 | col_r2<<16 | col_r3<<24
 *
 * This matches the byte ordering expected by aes32esmi (byte 0 = bits 7:0 = row 0).
 *
 * ShiftRows mapping
 * -----------------
 * After ShiftRows, output column j needs:
 *   byte 0 (row 0): from s[j]         byte 0  (row 0 no shift)
 *   byte 1 (row 1): from s[(j+1)%4]   byte 1  (row 1 shifts left by 1)
 *   byte 2 (row 2): from s[(j+2)%4]   byte 2  (row 2 shifts left by 2)
 *   byte 3 (row 3): from s[(j+3)%4]   byte 3  (row 3 shifts left by 3)
 *
 * So for each output column j we issue 4 aes32esmi instructions, each time
 * selecting a different source column and byte position (= the same bs value).
 *
 * Compilation
 * -----------
 * Build with MARCH containing 'zkne', e.g.:
 *   make clean_all exe MARCH=rv32imc_zkne_zknd_zicsr_zifencei
 *
 * GCC defines __riscv_zkne when zkne is part of the ISA.
 * If not defined, this file falls back to the software AES path.
 */

#include <stdint.h>
#include <string.h>
#include "aes.h"
#include "aes_zkne.h"

/* -------------------------------------------------------------------------
 * Fallback: no Zkne – delegate to tiny-AES-c
 * ---------------------------------------------------------------------- */
#ifndef __riscv_zkne

void aes128_ecb_encrypt_zkne_rk(const uint32_t *rk,
                                 const uint8_t in[16],
                                 uint8_t out[16]) {
  /* Fallback: rk is from AES_init_ctx, use tiny-AES-c encrypt */
  struct AES_ctx ctx;
  memcpy(ctx.RoundKey, rk, 176);
  memcpy(out, in, 16);
  AES_ECB_encrypt(&ctx, out);
}

void aes128_ecb_encrypt_zkne(const uint8_t key[16],
                              const uint8_t in[16],
                              uint8_t out[16]) {
  struct AES_ctx ctx;
  uint8_t tmp[16];
  memcpy(tmp, in, 16);
  AES_init_ctx(&ctx, key);
  AES_ECB_encrypt(&ctx, tmp);
  memcpy(out, tmp, 16);
}

#else  /* __riscv_zkne defined ------------------------------------------- */

/* -------------------------------------------------------------------------
 * Inline-assembly wrappers
 * bs must be a compile-time constant (2-bit immediate in the encoding)
 * ---------------------------------------------------------------------- */

/* aes32esmi – mid-round: SubBytes + ShiftRows contrib + MixColumns */
#define ESMI(rd, rs1, rs2, bs) \
  __asm__ volatile("aes32esmi %0, %1, %2, " #bs \
                   : "=r"(rd) : "r"(rs1), "r"(rs2))

/* aes32esi – final round: SubBytes + ShiftRows contrib, no MixColumns */
#define ESI(rd, rs1, rs2, bs) \
  __asm__ volatile("aes32esi %0, %1, %2, " #bs \
                   : "=r"(rd) : "r"(rs1), "r"(rs2))

/* -------------------------------------------------------------------------
 * Helper: pack/unpack a 4-byte column to/from uint32_t
 * ---------------------------------------------------------------------- */
static inline uint32_t col_load(const uint8_t *p) {
  /* On little-endian RISC-V this compiles to a single LW if aligned. */
  return (uint32_t)p[0]
       | ((uint32_t)p[1] <<  8)
       | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
}

static inline void col_store(uint8_t *p, uint32_t w) {
  p[0] = (uint8_t)(w);
  p[1] = (uint8_t)(w >>  8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
}

/* -------------------------------------------------------------------------
 * Core Cipher  (operates on 16-byte buffer in-place)
 *
 * Round key layout (from tiny-AES-c KeyExpansion):
 *   RoundKey[4*(r*4 + c) ... +3] = round r, column c, bytes 0-3
 * Casting to uint32_t gives rk[r*4 + c] on little-endian = same byte order.
 * ---------------------------------------------------------------------- */
static void Cipher_zkne(uint8_t buf[16], const uint32_t *rk) {

  /* Load state columns into registers */
  uint32_t s0 = col_load(buf +  0);
  uint32_t s1 = col_load(buf +  4);
  uint32_t s2 = col_load(buf +  8);
  uint32_t s3 = col_load(buf + 12);

  /* --- Round 0: AddRoundKey only --- */
  s0 ^= rk[0];  s1 ^= rk[1];  s2 ^= rk[2];  s3 ^= rk[3];

  /* --- Rounds 1-9: SubBytes + ShiftRows + MixColumns + AddRoundKey ---
   *
   * Output column j = esmi(esmi(esmi(esmi(rk[j],
   *                    s[j],       0),     <- row 0, no shift
   *                    s[(j+1)%4], 1),     <- row 1, contribute from col j+1
   *                    s[(j+2)%4], 2),
   *                    s[(j+3)%4], 3)
   */
  uint32_t t0, t1, t2, t3;

#define MID_ROUND(base) \
  ESMI(t0, rk[(base)+0], s0, 0); \
  ESMI(t0, t0,           s1, 1); \
  ESMI(t0, t0,           s2, 2); \
  ESMI(t0, t0,           s3, 3); \
  \
  ESMI(t1, rk[(base)+1], s1, 0); \
  ESMI(t1, t1,           s2, 1); \
  ESMI(t1, t1,           s3, 2); \
  ESMI(t1, t1,           s0, 3); \
  \
  ESMI(t2, rk[(base)+2], s2, 0); \
  ESMI(t2, t2,           s3, 1); \
  ESMI(t2, t2,           s0, 2); \
  ESMI(t2, t2,           s1, 3); \
  \
  ESMI(t3, rk[(base)+3], s3, 0); \
  ESMI(t3, t3,           s0, 1); \
  ESMI(t3, t3,           s1, 2); \
  ESMI(t3, t3,           s2, 3); \
  \
  s0 = t0; s1 = t1; s2 = t2; s3 = t3;

  MID_ROUND(4)   /* round 1  */
  MID_ROUND(8)   /* round 2  */
  MID_ROUND(12)  /* round 3  */
  MID_ROUND(16)  /* round 4  */
  MID_ROUND(20)  /* round 5  */
  MID_ROUND(24)  /* round 6  */
  MID_ROUND(28)  /* round 7  */
  MID_ROUND(32)  /* round 8  */
  MID_ROUND(36)  /* round 9  */

#undef MID_ROUND

  /* --- Round 10: SubBytes + ShiftRows + AddRoundKey (no MixColumns) --- */
  ESI(t0, rk[40], s0, 0);
  ESI(t0, t0,     s1, 1);
  ESI(t0, t0,     s2, 2);
  ESI(t0, t0,     s3, 3);

  ESI(t1, rk[41], s1, 0);
  ESI(t1, t1,     s2, 1);
  ESI(t1, t1,     s3, 2);
  ESI(t1, t1,     s0, 3);

  ESI(t2, rk[42], s2, 0);
  ESI(t2, t2,     s3, 1);
  ESI(t2, t2,     s0, 2);
  ESI(t2, t2,     s1, 3);

  ESI(t3, rk[43], s3, 0);
  ESI(t3, t3,     s0, 1);
  ESI(t3, t3,     s1, 2);
  ESI(t3, t3,     s2, 3);

  /* Store result */
  col_store(buf +  0, t0);
  col_store(buf +  4, t1);
  col_store(buf +  8, t2);
  col_store(buf + 12, t3);
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */
/*
 * Encrypt-only: uses pre-expanded round keys.
 * Call AES_init_ctx() once, then this for each block.
 */
void aes128_ecb_encrypt_zkne_rk(const uint32_t *rk,
                                 const uint8_t in[16],
                                 uint8_t out[16]) {
  memcpy(out, in, 16);
  Cipher_zkne(out, rk);
}

void aes128_ecb_encrypt_zkne(const uint8_t key[16],
                              const uint8_t in[16],
                              uint8_t out[16]) {
  /* Reuse tiny-AES-c key schedule (same expanded key layout) */
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, key);

  memcpy(out, in, 16);

  /* Cast RoundKey to uint32_t* – safe: it is the first member of AES_ctx,
   * so the struct (and hence RoundKey) is at least 4-byte aligned. */
  Cipher_zkne(out, (const uint32_t *)ctx.RoundKey);
}

#endif /* __riscv_zkne */
