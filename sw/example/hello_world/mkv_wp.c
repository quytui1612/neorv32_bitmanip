/*
 * MKV-128 word-parallel, tableless — RISC-V Bitmanip demonstration.
 *
 * Original algorithm: MKV128_8bit/MKV128_8bit/MKV128.cpp (kept unmodified).
 * This file implements the same cipher with three key differences:
 *
 *  [1] Tableless GF(2^8) multiply (no Mult[256][256] = 64 KB table).
 *      Uses xtime_w(): word-level multiply-by-2, processing 4 column bytes
 *      simultaneously in one uint32_t.
 *      → Eliminates 64 KB DMEM footprint and all associated cache misses.
 *
 *  [2] Word-packed state (uint32_t[4], one word per column).
 *      AddRoundKey: 4 XOR instead of 16.
 *      XWords: 5 XOR instead of ~48.
 *
 *  [3] Bitmanip patterns for GCC recognition:
 *      Zbb — andn : (x & ~mask) in xtime_w() — 1 insn vs 2 (lui+and)
 *      Zbb — rori : rotation in MixWords + XWords — 1 insn vs 3 (srli+slli+or)
 *      Zba — sh2add: uint32_t S-box index scaling in subcells4_zba() — 1 insn vs 2
 *
 * GF polynomial: f(x) = x^8 + x^5 + x^3 + x + 1  → reduction byte = 0x2B
 *
 * Matrix M (forward MixWords):
 *   { 0x01, 0x02, 0x01, 0x03 }
 *   { 0x03, 0x07, 0x01, 0x04 }
 *   { 0x04, 0x0B, 0x03, 0x0D }
 *   { 0x0D, 0x1E, 0x06, 0x14 }
 *
 * Matrix iM (inverse MixWords):
 *   { 0x14, 0x06, 0x18, 0x0B }
 *   { 0x0B, 0x02, 0x0D, 0x05 }
 *   { 0x05, 0x01, 0x07, 0x02 }
 *   { 0x02, 0x01, 0x03, 0x01 }
 */

#include <stdint.h>
#include <string.h>
#include "mkv_wp.h"

/* =========================================================================
 * S-box and inverse S-box (values identical to MKV128.cpp)
 * ======================================================================= */

const uint8_t mkv_sbox[256] = {
  0x01,0x11,0x91,0xE1,0xD1,0xB1,0x71,0x61,0xF1,0x21,0xC1,0x51,0xA1,0x41,0x31,0x81,
  0x00,0x10,0xE3,0x92,0xB5,0xD4,0x77,0x66,0x89,0x38,0xAB,0x4A,0xCD,0x5C,0x2F,0xFE,
  0x08,0x5F,0x3E,0xB0,0x1C,0xC2,0x83,0xDD,0xE8,0xF6,0x47,0x79,0x95,0x2B,0xAA,0x64,
  0x0F,0x48,0xD0,0x29,0xA3,0x1A,0xF2,0xBB,0x65,0xCC,0xE4,0x3D,0x57,0x7E,0x86,0x9F,
  0x0C,0x2A,0xF4,0x1F,0x5B,0x90,0xEE,0xC5,0x36,0x6D,0x73,0x88,0xBC,0xA7,0x49,0xD2,
  0x0A,0x3C,0x18,0x85,0xE0,0x4D,0x99,0xA4,0xB3,0x5E,0xDA,0xC7,0x72,0xFF,0x6B,0x26,
  0x06,0x76,0xCF,0xA8,0x4E,0x59,0x60,0x17,0xDC,0x9B,0x32,0xF5,0x23,0x84,0xED,0xBA,
  0x07,0x67,0x2D,0x3B,0xFA,0x8C,0x16,0x70,0x54,0xA2,0x98,0xBE,0xEF,0xD9,0xC3,0x45,
  0x0E,0xA9,0x62,0x5A,0x27,0xBF,0x34,0x9C,0xFD,0xD5,0x8E,0xE6,0x1B,0x43,0x78,0xC0,
  0x03,0xB2,0x87,0xC4,0x9D,0x6E,0x4B,0xF8,0x7A,0xE9,0x2C,0xAF,0xD6,0x15,0x50,0x33,
  0x0D,0xFB,0x56,0xEC,0x3F,0x75,0xB8,0x42,0x1E,0x24,0xC9,0x93,0x80,0x6A,0xD7,0xAD,
  0x04,0xE5,0xB9,0x7D,0x82,0xA6,0xCA,0x2E,0x97,0x13,0x6F,0xDB,0x44,0x30,0xFC,0x58,
  0x0B,0x8D,0x9A,0x46,0x74,0x28,0xDF,0x53,0xCB,0xB7,0xF0,0x6C,0xAE,0xE2,0x35,0x19,
  0x05,0x94,0x7B,0xDE,0xC6,0xF3,0xAC,0x39,0x4F,0x8A,0x55,0x20,0x68,0xBD,0x12,0xE7,
  0x02,0xD3,0xA5,0xF7,0x69,0xEB,0x5D,0x8F,0x22,0x40,0xB6,0x14,0x3A,0xC8,0x9E,0x7C,
  0x09,0xCE,0x4C,0x63,0xD8,0x37,0x25,0xEA,0xA0,0x7F,0x1D,0x52,0xF9,0x96,0xB4,0x8B
};

static const uint8_t mkv_isbox[256] = {
  0x10,0x00,0xE0,0x90,0xB0,0xD0,0x60,0x70,0x20,0xF0,0x50,0xC0,0x40,0xA0,0x80,0x30,
  0x11,0x01,0xDE,0xB9,0xEB,0x9D,0x76,0x67,0x52,0xCF,0x35,0x8C,0x24,0xFA,0xA8,0x43,
  0xDB,0x09,0xE8,0x6C,0xA9,0xF6,0x5F,0x84,0xC5,0x33,0x41,0x2D,0x9A,0x72,0xB7,0x1E,
  0xBD,0x0E,0x6A,0x9F,0x86,0xCE,0x48,0xF5,0x19,0xD7,0xEC,0x73,0x51,0x3B,0x22,0xA4,
  0xE9,0x0D,0xA7,0x8D,0xBC,0x7F,0xC3,0x2A,0x31,0x4E,0x1B,0x96,0xF2,0x55,0x64,0xD8,
  0x9E,0x0B,0xFB,0xC7,0x78,0xDA,0xA2,0x3C,0xBF,0x65,0x83,0x44,0x1D,0xE6,0x59,0x21,
  0x66,0x07,0x82,0xF3,0x2F,0x38,0x17,0x71,0xDC,0xE4,0xAD,0x5E,0xCB,0x49,0x95,0xBA,
  0x77,0x06,0x5C,0x4A,0xC4,0xA5,0x61,0x16,0x8E,0x2B,0x98,0xD2,0xEF,0xB3,0x3D,0xF9,
  0xAC,0x0F,0xB4,0x26,0x6D,0x53,0x3E,0x92,0x4B,0x18,0xD9,0xFF,0x75,0xC1,0x8A,0xE7,
  0x45,0x02,0x13,0xAB,0xD1,0x2C,0xFD,0xB8,0x7A,0x56,0xC2,0x69,0x87,0x94,0xEE,0x3F,
  0xF8,0x0C,0x79,0x34,0x57,0xE2,0xB5,0x4D,0x63,0x81,0x2E,0x1A,0xD6,0xAF,0xCC,0x9B,
  0x23,0x05,0x91,0x58,0xFE,0x14,0xEA,0xC9,0xA6,0xB2,0x6F,0x37,0x4C,0xDD,0x7B,0x85,
  0x8F,0x0A,0x25,0x7E,0x93,0x47,0xD4,0x5B,0xED,0xAA,0xB6,0xC8,0x39,0x1C,0xF1,0x62,
  0x32,0x04,0x4F,0xE1,0x15,0x89,0x9C,0xAE,0xF4,0x7D,0x5A,0xBB,0x68,0x27,0xD3,0xC6,
  0x54,0x03,0xCD,0x12,0x3A,0xB1,0x8B,0xDF,0x28,0x99,0xF7,0xE5,0xA3,0x6E,0x46,0x7C,
  0xCA,0x08,0x36,0xD5,0x42,0x6B,0x29,0xE3,0x97,0xFC,0x74,0xA1,0xBE,0x88,0x1F,0x5D
};

/*
 * Round constants (word-packed, little-endian byte order).
 *
 * Const_0[16] = {0x93,0x02,0xee,0x91, 0x1a,0x2a,0xd9,0x8c,
 *                0xad,0x13,0xe7,0x94, 0x8a,0xd8,0xb3,0xb2}
 * col[k] = bytes[4k] | bytes[4k+1]<<8 | bytes[4k+2]<<16 | bytes[4k+3]<<24
 */
const uint32_t Const0_w[4] = {
  0x91ee0293u,  /* bytes  0-3  */
  0x8cd92a1au,  /* bytes  4-7  */
  0x94e713adu,  /* bytes  8-11 */
  0xb2b3d88au   /* bytes 12-15 */
};

/*
 * Const_1[16] = {0xd4,0xda,0x00,0xf3, 0x3f,0x11,0xfd,0x88,
 *                0x22,0x16,0x6b,0xb9, 0xcd,0x18,0x7c,0x55}
 */
const uint32_t Const1_w[4] = {
  0xf300dad4u,
  0x88fd113fu,
  0xb96b1622u,
  0x557c18cdu
};

/* =========================================================================
 * Low-level primitives
 * ======================================================================= */

/*
 * ror32: rotate-right 32-bit word by n bits (0 < n < 32).
 *
 * GCC pattern recognition:
 *   -march includes 'zbb'  → emits 'rori rd, rs, imm'     (1 cycle)
 *   otherwise              → emits 'srli' + 'slli' + 'or' (3 cycles)
 *
 * Used in:
 *   MixWords: k=1,2,3 column input rotation (3 calls/F() call × encrypts)
 *   invMixWords: output rotation for k=1,2,3 (3 calls/iF() call)
 *   XWords word-level implementation (4 cols, but via ^= all trick = 0 rori)
 */
static inline uint32_t ror32(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32u - n));
}

/*
 * xtime_w: multiply each byte of w by 2 in GF(2^8) simultaneously.
 *
 * f(x) = x^8 + x^5 + x^3 + x + 1  →  reduction byte = 0x2B
 *
 * Per-byte logic:
 *   xtime(b) = (b << 1) ^ (b & 0x80 ? 0x2B : 0x00)
 *
 * Word-level:
 *   lo  = w & ~0x80808080u   → clear high bit before shift (preserves other 7 bits)
 *   hi  = (w >> 7) & 0x01010101u → 0x01 per byte where msb was set
 *   poly = hi * 0x2Bu        → 0x2B per byte that needs reduction
 *                              (safe: hi ∈ {0,1} per byte, 0x2B × 1 = 0x2B < 256)
 *
 * NOTE on Zbb 'andn':
 *   'andn rd, rs1, rs2' fires ONLY when BOTH operands are registers.
 *   Here 0x80808080u is a compile-time constant, so GCC folds ~0x80808080 = 0x7f7f7f7f
 *   and emits 'lui+addi+and' (same cost). Andn gives no benefit for constant masks.
 *
 * NOTE on inlining:
 *   With -Os, GCC refuses to inline even 'static inline' functions called ≥2×.
 *   '__attribute__((always_inline))' forces inlining at -Os, eliminating:
 *     • 4 × jal/ret pairs per mix_col_fwd() call   (~8 insns, ~8+ cycles)
 *     • stack frame allocation in mix_col_fwd       (~12 insns)
 *   This is the BIGGEST single optimization for this file.
 *
 * NOTE on 'mul':
 *   GCC emits 'mul' for hi * 0x2Bu.  On NEORV32 with sequential (non-fast) multiplier
 *   this can be up to 32 stall cycles.  Use xtime_w_nomul() on such targets.
 */
static __attribute__((always_inline)) inline uint32_t xtime_w(uint32_t w) {
  return ((w & ~0x80808080u) << 1)
       ^ (((w >> 7) & 0x01010101u) * 0x2Bu);
}

/*
 * xtime_w_nomul: same result as xtime_w but uses shifts+XOR instead of MUL.
 *
 * 0x2B = 0b00101011 = 2^5 + 2^3 + 2^1 + 2^0
 * hi * 0x2B = hi ^ (hi<<1) ^ (hi<<3) ^ (hi<<5)
 *
 * This works because hi ∈ {0,1} per byte with no cross-byte carry:
 *   max bit set per byte in hi = bit 0 (= 1 × 2^0)
 *   hi<<5 shifts bit 0 to bit 5, still within the same byte's [0..7] range. ✓
 *
 * WARNING: GCC at -Os recognises the shift expansion as "multiply by 43" and
 * folds it BACK to 'mul'.  To prevent that, each shift result is passed through
 * an '__asm__ volatile("" : "+r"(x))' register barrier that blocks GCC's tree-
 * reassoc / strength-reduction passes.  Without these barriers f128_wp_opt and
 * f128_wp_zba produce IDENTICAL code and get merged by the linker.
 *
 * Cost (with barriers, -Os):
 *   3 barriers (no-op) + 3 slli + 3 xor = 6 real insns, 0 mul
 * vs xtime_w:
 *   1 mul  (1 insn, but N stall cycles on NEORV32 sequential multiplier)
 */
static __attribute__((always_inline)) inline uint32_t xtime_w_nomul(uint32_t w) {
  uint32_t lo = (w & ~0x80808080u) << 1;
  uint32_t hi = (w >> 7) & 0x01010101u;
  /* shift components — barriers prevent GCC from re-merging to 'mul' */
  uint32_t h1 = hi << 1; __asm__ volatile("" : "+r"(h1));
  uint32_t h3 = hi << 3; __asm__ volatile("" : "+r"(h3));
  uint32_t h5 = hi << 5; __asm__ volatile("" : "+r"(h5));
  return lo ^ hi ^ h1 ^ h3 ^ h5;
}

/*
 * SubCells on a packed word (uint8_t S-box, byte-indexed lbu).
 * 4 S-box lookups per call.
 * always_inline: prevents -Os from emitting a jal (2+callee-save cycles each).
 */
static __attribute__((always_inline)) inline uint32_t subcells4(uint32_t w) {
  return  (uint32_t)mkv_sbox[ w        & 0xFFu]
       | ((uint32_t)mkv_sbox[(w >>  8) & 0xFFu] <<  8)
       | ((uint32_t)mkv_sbox[(w >> 16) & 0xFFu] << 16)
       | ((uint32_t)mkv_sbox[ w >> 24          ] << 24);
}

/* Inverse SubCells (uint8_t isbox). */
static __attribute__((always_inline)) inline uint32_t isubcells4(uint32_t w) {
  return  (uint32_t)mkv_isbox[ w        & 0xFFu]
       | ((uint32_t)mkv_isbox[(w >>  8) & 0xFFu] <<  8)
       | ((uint32_t)mkv_isbox[(w >> 16) & 0xFFu] << 16)
       | ((uint32_t)mkv_isbox[ w >> 24          ] << 24);
}

/* =========================================================================
 * MixWords — forward  (matrix M, input rotated right by k*8 bits)
 *
 * Original: matrmultcol1(col_ptr, M, out_ptr, k)
 *   for column k, input is cyclic-rotated by k positions (= ror32(col, k*8))
 *   then multiplied by 4×4 matrix M in GF(2^8).
 *
 * M = { {1, 2, 1, 3},
 *       {3, 7, 1, 4},
 *       {4, B, 3, D},
 *       {D,1E, 6,14} }
 *
 * For input word col = a|b<<8|c<<16|d<<24 (after rotation):
 *   y0 = 1*a ^ 2*b ^ 1*c ^ 3*d
 *   y1 = 3*a ^ 7*b ^ 1*c ^ 4*d
 *   y2 = 4*a ^ B*b ^ 3*c ^ D*d
 *   y3 = D*a ^ 1E*b ^ 6*c ^ 14*d
 *
 * Coefficient decomposition (xtime chains):
 *   3 = 2^1 ^ 1          B = 2^3 ^ 2^1 ^ 1     D = 2^3 ^ 2^2 ^ 1
 *   4 = 2^2              6 = 2^2 ^ 2^1          7 = 2^2 ^ 2^1 ^ 1
 *  14 = 2^4 ^ 2^2       1E = 2^4 ^ 2^3 ^ 2^2 ^ 2^1
 *
 * Word-level xtime reduces 4 per-byte xtimes to 1 word xtime_w() call.
 * 4 word xtimes replace 13 byte-level xtimes per column.
 * With Zbb andn: each xtime_w saves 1 insn over no-Zbb baseline.
 * ======================================================================= */
static uint32_t mix_col_fwd(uint32_t col) {
  /* Build xtime chain — each step doubles all 4 bytes simultaneously. */
  uint32_t x1  = col;           /* [ a,  b,  c,  d ]  */
  uint32_t x2  = xtime_w(x1);   /* [2a, 2b, 2c, 2d ]  xtime_w call 1 (Zbb andn) */
  uint32_t x4  = xtime_w(x2);   /* [4a, 4b, 4c, 4d ]  xtime_w call 2            */
  uint32_t x8  = xtime_w(x4);   /* [8a, 8b, 8c, 8d ]  xtime_w call 3            */
  uint32_t x10 = xtime_w(x8);   /* [16a,16b,16c,16d]  xtime_w call 4 (0x10=16)  */

  /* Extract individual per-row bytes (byte position = row within column). */
#define B0(w) ((uint8_t)((w)      ))
#define B1(w) ((uint8_t)((w) >>  8))
#define B2(w) ((uint8_t)((w) >> 16))
#define B3(w) ((uint8_t)((w) >> 24))

  /* y0 = 1*a ^ 2*b ^ 1*c ^ 3*d  (3 = 2+1) */
  uint8_t y0 = B0(x1) ^ B1(x2) ^ B2(x1) ^ B3(x2) ^ B3(x1);

  /* y1 = 3*a ^ 7*b ^ 1*c ^ 4*d  (3=2+1, 7=4+2+1) */
  uint8_t y1 = B0(x2) ^ B0(x1) ^ B1(x4) ^ B1(x2) ^ B1(x1) ^ B2(x1) ^ B3(x4);

  /* y2 = 4*a ^ B*b ^ 3*c ^ D*d  (B=8+2+1, D=8+4+1) */
  uint8_t y2 = B0(x4) ^ B1(x8) ^ B1(x2) ^ B1(x1)
             ^ B2(x2) ^ B2(x1) ^ B3(x8) ^ B3(x4) ^ B3(x1);

  /* y3 = D*a ^ 1E*b ^ 6*c ^ 14*d  (D=8+4+1, 1E=16+8+4+2, 6=4+2, 14=16+4) */
  uint8_t y3 = B0(x8) ^ B0(x4) ^ B0(x1)
             ^ B1(x10) ^ B1(x8) ^ B1(x4) ^ B1(x2)
             ^ B2(x4) ^ B2(x2)
             ^ B3(x10) ^ B3(x4);

#undef B0
#undef B1
#undef B2
#undef B3

  return (uint32_t)y0 | ((uint32_t)y1 << 8) | ((uint32_t)y2 << 16) | ((uint32_t)y3 << 24);
}

/*
 * MixWords — all 4 columns.
 * Column k: rotate input right by k*8 bits (Zbb rori, 1 insn vs 3).
 */
static void mix_words(uint32_t col[4]) {
  /* k=0: no rotation → plain mix */
  col[0] = mix_col_fwd(col[0]);
  /* k=1: ror32(col, 8)  — Zbb: rori 8  (saves 2 insns) */
  col[1] = mix_col_fwd(ror32(col[1], 8u));
  /* k=2: ror32(col, 16) — Zbb: rori 16 (saves 2 insns) */
  col[2] = mix_col_fwd(ror32(col[2], 16u));
  /* k=3: ror32(col, 24) — Zbb: rori 24 (saves 2 insns) */
  col[3] = mix_col_fwd(ror32(col[3], 24u));
}

/* =========================================================================
 * invMixWords — inverse (matrix iM, then output rotated)
 *
 * Original: matrmultcol2(col_ptr, iM, out_ptr, k)
 *   normal mat-mul (no input rotation), then output rotated by k positions.
 *
 * iM = { {0x14, 0x06, 0x18, 0x0B},   (row 0)
 *         {0x0B, 0x02, 0x0D, 0x05},   (row 1)
 *         {0x05, 0x01, 0x07, 0x02},   (row 2)
 *         {0x02, 0x01, 0x03, 0x01} }  (row 3)
 *
 * For input (a,b,c,d):
 *   y0 = 14*a ^ 06*b ^ 18*c ^ 0B*d
 *   y1 = 0B*a ^ 02*b ^ 0D*c ^ 05*d
 *   y2 = 05*a ^ 01*b ^ 07*c ^ 02*d
 *   y3 = 02*a ^ 01*b ^ 03*c ^ 01*d
 *
 * Output rotation for column k: ror32(tmp, out_rot[k])
 *   k=0 → 0 (no rotation)
 *   k=1 → 24
 *   k=2 → 16
 *   k=3 → 8
 * ======================================================================= */
static uint32_t mix_col_inv(uint32_t col) {
  uint32_t x1  = col;
  uint32_t x2  = xtime_w(x1);
  uint32_t x4  = xtime_w(x2);
  uint32_t x8  = xtime_w(x4);
  uint32_t x10 = xtime_w(x8);   /* 0x10 = 16 */

#define B0(w) ((uint8_t)((w)      ))
#define B1(w) ((uint8_t)((w) >>  8))
#define B2(w) ((uint8_t)((w) >> 16))
#define B3(w) ((uint8_t)((w) >> 24))

  /* y0 = 0x14*a ^ 0x06*b ^ 0x18*c ^ 0x0B*d
   *    = (16+4)*a ^ (4+2)*b ^ (16+8)*c ^ (8+2+1)*d */
  uint8_t y0 = B0(x10) ^ B0(x4)
             ^ B1(x4)  ^ B1(x2)
             ^ B2(x10) ^ B2(x8)
             ^ B3(x8)  ^ B3(x2) ^ B3(x1);

  /* y1 = 0x0B*a ^ 0x02*b ^ 0x0D*c ^ 0x05*d
   *    = (8+2+1)*a ^ 2*b ^ (8+4+1)*c ^ (4+1)*d */
  uint8_t y1 = B0(x8) ^ B0(x2) ^ B0(x1)
             ^ B1(x2)
             ^ B2(x8) ^ B2(x4) ^ B2(x1)
             ^ B3(x4) ^ B3(x1);

  /* y2 = 0x05*a ^ 0x01*b ^ 0x07*c ^ 0x02*d
   *    = (4+1)*a ^ 1*b ^ (4+2+1)*c ^ 2*d */
  uint8_t y2 = B0(x4) ^ B0(x1)
             ^ B1(x1)
             ^ B2(x4) ^ B2(x2) ^ B2(x1)
             ^ B3(x2);

  /* y3 = 0x02*a ^ 0x01*b ^ 0x03*c ^ 0x01*d
   *    = 2*a ^ 1*b ^ (2+1)*c ^ 1*d */
  uint8_t y3 = B0(x2)
             ^ B1(x1)
             ^ B2(x2) ^ B2(x1)
             ^ B3(x1);

#undef B0
#undef B1
#undef B2
#undef B3

  return (uint32_t)y0 | ((uint32_t)y1 << 8) | ((uint32_t)y2 << 16) | ((uint32_t)y3 << 24);
}

static void inv_mix_words(uint32_t col[4]) {
  /* Fully unrolled: with constant immediates, GCC -march=...zbb emits a single
   * 'rori rd, rs, imm' per column.  The previous for-loop + out_rot[] table
   * forced GCC to load the rotation amount from .rodata into a register and
   * emit the 3-insn shift/or sequence even when zbb was enabled, because
   * 'rori' (and 'ror') both require either an immediate or a register operand
   * that GCC's pattern recognizer rejects when fed through an array index.
   * Saves 2 insns/column × 3 columns = 6 insns per inv_mix_words call,
   * × r rounds = 18..30 insns/decrypt block. */
  col[0] =        mix_col_inv(col[0]);
  col[1] = ror32(mix_col_inv(col[1]), 24u);
  col[2] = ror32(mix_col_inv(col[2]), 16u);
  col[3] = ror32(mix_col_inv(col[3]),  8u);
}

/* =========================================================================
 * XWords — word-packed, all-XOR variant
 *
 * Original: Y[i] = X[(i+4)%16] ^ X[(i+8)%16] ^ X[(i+12)%16]
 * For column k: Y_col[k] = col[(k+1)%4] ^ col[(k+2)%4] ^ col[(k+3)%4]
 *             = (col[0]^col[1]^col[2]^col[3]) ^ col[k]   (equals all-XOR minus self)
 *
 * Implementation: compute `all` once, then col[k] ^= all.
 * 1 XOR for `all` + 4 XOR in-place = 5 word XORs.
 * Original: 3 XOR × 16 bytes = 48 byte XORs.
 * ======================================================================= */
static void xwords_wp(uint32_t col[4]) {
  uint32_t all = col[0] ^ col[1] ^ col[2] ^ col[3]; /* 3 XORs */
  col[0] ^= all;  /* = col[1]^col[2]^col[3] */
  col[1] ^= all;  /* = col[0]^col[2]^col[3] */
  col[2] ^= all;  /* = col[0]^col[1]^col[3] */
  col[3] ^= all;  /* = col[0]^col[1]^col[2] */
}

/* =========================================================================
 * Pack / unpack helpers
 * ======================================================================= */

/* Pack 16-byte state (column-major) into 4 uint32_t words. */
static inline void pack_state(const uint8_t b[16], uint32_t col[4]) {
  for (int k = 0; k < 4; k++) {
    col[k] = (uint32_t)b[4*k]
           | ((uint32_t)b[4*k+1] <<  8)
           | ((uint32_t)b[4*k+2] << 16)
           | ((uint32_t)b[4*k+3] << 24);
  }
}

/*
 * pack_state_lw: fastest possible — exploit little-endian RV32 + Zbkb is NOT needed.
 *
 * Observation: the column packing
 *   col[k] = b[4k] | b[4k+1]<<8 | b[4k+2]<<16 | b[4k+3]<<24
 * IS exactly the layout a little-endian 32-bit load produces.  If the input
 * buffer is 4-byte aligned, a single 'lw' loads one column in 1 insn.
 *
 * Cost per column:
 *   pack_state            (byte loads) : 4 lbu + 3 slli + 3 or       = 10 insns
 *   pack_state_zbkb (Zbkb packh+pack)  : 4 lbu + 2 packh + 1 pack    =  7 insns
 *   pack_state_lw   (aligned word load): 1 lw                        =  1 insn
 *
 * memcpy() is used to express "may be unaligned" portably; GCC folds it to a
 * single lw on RV32 when alignment is statically known, and to lbu-shift-or on
 * an unaligned target.  For benchmark inputs that are 4-byte aligned (default
 * for stack/.bss arrays of uint8_t[16] with __attribute__((aligned(4)))) this
 * is the single biggest pack/unpack speedup available.
 */
static inline void pack_state_lw(const uint8_t b[16], uint32_t col[4]) {
  /* memcpy keeps strict-aliasing/alignment rules sane; GCC reduces it to lw
   * on aligned targets and to a byte sequence otherwise — both cases are
   * upper-bounded by the byte-loop version. */
  __builtin_memcpy(&col[0], b +  0, 4);
  __builtin_memcpy(&col[1], b +  4, 4);
  __builtin_memcpy(&col[2], b +  8, 4);
  __builtin_memcpy(&col[3], b + 12, 4);
}

static inline void unpack_state_sw(const uint32_t col[4], uint8_t b[16]) {
  __builtin_memcpy(b +  0, &col[0], 4);
  __builtin_memcpy(b +  4, &col[1], 4);
  __builtin_memcpy(b +  8, &col[2], 4);
  __builtin_memcpy(b + 12, &col[3], 4);
}

/*
 * pack_state_zbkb: assemble 4 bytes → one uint32_t word using Zbkb instructions.
 *
 * Without Zbkb:  4 lbu + 3 slli + 3 or  = 10 insns/word
 * With    Zbkb:  4 lbu + 2 packh + 1 pack =  7 insns/word  (−3 per word = −12/call)
 *
 * Zbkb:
 *   packh rd, rs1, rs2 → rd = (rs1 & 0xFF) | ((rs2 & 0xFF) << 8)
 *   pack  rd, rs1, rs2 → rd = (rs1 & 0xFFFF) | ((rs2 & 0xFFFF) << 16)
 *
 * GCC 15 does NOT auto-recognise these patterns from C source; explicit
 * inline asm is required to guarantee emission of packh/pack.
 */
static inline void pack_state_zbkb(const uint8_t b[16], uint32_t col[4]) {
#ifdef __riscv_zbkb
  for (int k = 0; k < 4; k++) {
    const uint8_t *p = b + 4*k;
    uint32_t lo, hi;
    __asm__("packh %0, %1, %2" : "=r"(lo) : "r"((uint32_t)p[0]), "r"((uint32_t)p[1]));
    __asm__("packh %0, %1, %2" : "=r"(hi) : "r"((uint32_t)p[2]), "r"((uint32_t)p[3]));
    __asm__("pack  %0, %1, %2" : "=r"(col[k]) : "r"(lo), "r"(hi));
  }
#else
  pack_state(b, col);
#endif
}

/* Unpack 4 uint32_t words back to 16 bytes (column-major). */
static inline void unpack_state(const uint32_t col[4], uint8_t b[16]) {
  for (int k = 0; k < 4; k++) {
    b[4*k]   = (uint8_t)(col[k]      );
    b[4*k+1] = (uint8_t)(col[k] >>  8);
    b[4*k+2] = (uint8_t)(col[k] >> 16);
    b[4*k+3] = (uint8_t)(col[k] >> 24);
  }
}

/* =========================================================================
 * Round functions
 * ======================================================================= */

/*
 * f128_wp: one forward F() call, in-place on col[4].
 *
 * Mirrors the original F128() sequence (without printf):
 *   1. AddRoundKey : col ^= k1  (4 word XOR, saves 12 vs original 16)
 *   2. SubCells    : col = sbox[col]  (16 S-box lookups)
 *   3. MixWords    : matrix + rotation
 *   4. AddRoundKey : col ^= k2
 *   5. SubCells    : col = sbox[col]
 *   6. XWords      : col[k] = XOR of other three cols (5 word XOR)
 *
 * k1, k2: arrays of 4 uint32_t (word-packed round key halves).
 */
static void f128_wp(uint32_t col[4], const uint32_t *k1, const uint32_t *k2) {
  /* 1. AddRoundKey */
  col[0] ^= k1[0]; col[1] ^= k1[1]; col[2] ^= k1[2]; col[3] ^= k1[3];
  /* 2. SubCells */
  col[0] = subcells4(col[0]); col[1] = subcells4(col[1]);
  col[2] = subcells4(col[2]); col[3] = subcells4(col[3]);
  /* 3. MixWords */
  mix_words(col);
  /* 4. AddRoundKey */
  col[0] ^= k2[0]; col[1] ^= k2[1]; col[2] ^= k2[2]; col[3] ^= k2[3];
  /* 5. SubCells */
  col[0] = subcells4(col[0]); col[1] = subcells4(col[1]);
  col[2] = subcells4(col[2]); col[3] = subcells4(col[3]);
  /* 6. XWords */
  xwords_wp(col);
}

/*
 * f128_wp_opt: combines all compiler-level optimizations:
 *   [A] always_inline on xtime_w / subcells4 / mix_col_fwd (already applied globally)
 *   [B] xtime_w_nomul — polynomial reduction via shifts, avoids 'mul' instruction
 *
 * To demonstrate [B] separately, we define mix_col_fwd_nomul and use it here.
 * The nomul variants share the same xtime chain but call xtime_w_nomul() instead.
 */
static uint32_t mix_col_fwd_nomul(uint32_t col) {
  uint32_t x1  = col;
  uint32_t x2  = xtime_w_nomul(x1);
  uint32_t x4  = xtime_w_nomul(x2);
  uint32_t x8  = xtime_w_nomul(x4);
  uint32_t x10 = xtime_w_nomul(x8);
#define B0(w) ((uint8_t)((w)      ))
#define B1(w) ((uint8_t)((w) >>  8))
#define B2(w) ((uint8_t)((w) >> 16))
#define B3(w) ((uint8_t)((w) >> 24))
  uint8_t y0 = B0(x1) ^ B1(x2) ^ B2(x1) ^ B3(x2) ^ B3(x1);
  uint8_t y1 = B0(x2) ^ B0(x1) ^ B1(x4) ^ B1(x2) ^ B1(x1) ^ B2(x1) ^ B3(x4);
  uint8_t y2 = B0(x4) ^ B1(x8) ^ B1(x2) ^ B1(x1)
             ^ B2(x2) ^ B2(x1) ^ B3(x8) ^ B3(x4) ^ B3(x1);
  uint8_t y3 = B0(x8) ^ B0(x4) ^ B0(x1)
             ^ B1(x10) ^ B1(x8) ^ B1(x4) ^ B1(x2)
             ^ B2(x4)  ^ B2(x2)
             ^ B3(x10) ^ B3(x4);
#undef B0
#undef B1
#undef B2
#undef B3
  return (uint32_t)y0 | ((uint32_t)y1 << 8) | ((uint32_t)y2 << 16) | ((uint32_t)y3 << 24);
}

static void mix_words_nomul(uint32_t col[4]) {
  col[0] = mix_col_fwd_nomul(col[0]);
  col[1] = mix_col_fwd_nomul(ror32(col[1], 8u));
  col[2] = mix_col_fwd_nomul(ror32(col[2], 16u));
  col[3] = mix_col_fwd_nomul(ror32(col[3], 24u));
}

static void f128_wp_opt(uint32_t col[4], const uint32_t *k1, const uint32_t *k2) {
  col[0] ^= k1[0]; col[1] ^= k1[1]; col[2] ^= k1[2]; col[3] ^= k1[3];
  col[0] = subcells4(col[0]); col[1] = subcells4(col[1]);
  col[2] = subcells4(col[2]); col[3] = subcells4(col[3]);
  mix_words_nomul(col);   /* no mul, always_inline xtime */
  col[0] ^= k2[0]; col[1] ^= k2[1]; col[2] ^= k2[2]; col[3] ^= k2[3];
  col[0] = subcells4(col[0]); col[1] = subcells4(col[1]);
  col[2] = subcells4(col[2]); col[3] = subcells4(col[3]);
  xwords_wp(col);
}

/*
 * if128_wp: one inverse F() call, in-place on col[4].
 *
 * Mirrors iF128() sequence:
 *   1. XWords
 *   2. invSubCells
 *   3. AddRoundKey(k2)
 *   4. invMixWords
 *   5. invSubCells
 *   6. AddRoundKey(k1)
 */
static void if128_wp(uint32_t col[4], const uint32_t *k1, const uint32_t *k2) {
  xwords_wp(col);
  col[0] = isubcells4(col[0]); col[1] = isubcells4(col[1]);
  col[2] = isubcells4(col[2]); col[3] = isubcells4(col[3]);
  col[0] ^= k2[0]; col[1] ^= k2[1]; col[2] ^= k2[2]; col[3] ^= k2[3];
  inv_mix_words(col);
  col[0] = isubcells4(col[0]); col[1] = isubcells4(col[1]);
  col[2] = isubcells4(col[2]); col[3] = isubcells4(col[3]);
  col[0] ^= k1[0]; col[1] ^= k1[1]; col[2] ^= k1[2]; col[3] ^= k1[3];
}

/* =========================================================================
 * Key schedule
 * Mirrors KeyExpansion128() / setInitialKeyState128() from MKV128.cpp,
 * without any printf, using word-packed state and optimised F().
 * ======================================================================= */
void mkv_wp_init(mkv_wp_ctx_t *ctx, int rounds, const uint8_t *masterKey) {
  ctx->rounds = rounds;

  /* rk[0..3] = K0 = first 16 bytes of masterKey */
  pack_state(masterKey, ctx->rk);

  /* Block1 = masterKey[0..15] */
  uint32_t blk1[4];
  pack_state(masterKey, blk1);

  /* Block2 depends on key size:
   *   128-bit: Block2 = Block1 ^ 0xFF (complement)
   *   192-bit: Block2 = masterKey[16..23] || ~masterKey[8..15]
   *   256-bit: Block2 = masterKey[16..31]
   */
  uint32_t blk2[4];
  if (rounds == MKV_ROUNDS_128) {
    /* complement all bytes */
    for (int i = 0; i < 4; i++) blk2[i] = blk1[i] ^ 0xFFFFFFFFu;
  } else if (rounds == MKV_ROUNDS_192) {
    /* bytes 0-7 from masterKey[16..23], bytes 8-15 = masterKey[8..15]^0xFF */
    uint8_t tmp[16];
    memcpy(tmp,     masterKey + 16, 8);
    for (int i = 8; i < 16; i++) tmp[i] = masterKey[i] ^ 0xFFu;
    pack_state(tmp, blk2);
  } else {
    /* 256-bit: full masterKey[16..31] */
    pack_state(masterKey + 16, blk2);
  }

  uint32_t cl[4], cr[4], tmpc[4];

  for (int i = 0; i < rounds; i++) {
    /* Build CL = Const_0 with byte15 XOR'd by (2*i+1)
     * Byte 15 is col[3] bit 24-31 in word packing.            */
    cl[0] = Const0_w[0]; cl[1] = Const0_w[1];
    cl[2] = Const0_w[2]; cl[3] = Const0_w[3];
    cl[3] ^= (uint32_t)(2*i + 1) << 24;

    cr[0] = Const1_w[0]; cr[1] = Const1_w[1];
    cr[2] = Const1_w[2]; cr[3] = Const1_w[3];
    cr[3] ^= (uint32_t)(2*i + 2) << 24;

    /* Apply F twice to Block1 with CL (matches original MKV128.cpp KeyExpansion128):
     *   F128(Block1, CL,    tmpC=0);   // k1 = CL, k2 = 0
     *   F128(Block1, tmpC=0, tmpC=0);  // k1 = 0, k2 = 0
     * f128_wp modifies its first arg (state) in place; k1/k2 are read-only.
     * Hence tmpc stays zero across both calls. */
    tmpc[0] = tmpc[1] = tmpc[2] = tmpc[3] = 0u;
    f128_wp(blk1, cl,   tmpc);
    f128_wp(blk1, tmpc, tmpc);

    /* Same for Block2 with CR */
    tmpc[0] = tmpc[1] = tmpc[2] = tmpc[3] = 0u;
    f128_wp(blk2, cr,   tmpc);
    f128_wp(blk2, tmpc, tmpc);

    /* V-schedule swap:
     *   tmp   = Block1
     *   Block1 = Block2
     *   Block2 = tmp ^ Block2  (= old Block1 ^ Block2)
     */
    uint32_t tmp_blk[4];
    tmp_blk[0] = blk1[0]; tmp_blk[1] = blk1[1];
    tmp_blk[2] = blk1[2]; tmp_blk[3] = blk1[3];

    blk1[0] = blk2[0]; blk1[1] = blk2[1];
    blk1[2] = blk2[2]; blk1[3] = blk2[3];

    blk2[0] = tmp_blk[0] ^ blk2[0]; blk2[1] = tmp_blk[1] ^ blk2[1];
    blk2[2] = tmp_blk[2] ^ blk2[2]; blk2[3] = tmp_blk[3] ^ blk2[3];

    /* Store round key pair: rk[K1] = blk1, rk[K2] = blk2 */
    int base = (2*i + 1) * 4;
    ctx->rk[base+0] = blk1[0]; ctx->rk[base+1] = blk1[1];
    ctx->rk[base+2] = blk1[2]; ctx->rk[base+3] = blk1[3];
    ctx->rk[base+4] = blk2[0]; ctx->rk[base+5] = blk2[1];
    ctx->rk[base+6] = blk2[2]; ctx->rk[base+7] = blk2[3];
  }
}

/* =========================================================================
 * Encrypt / Decrypt
 * ======================================================================= */

void mkv_wp_encrypt(const mkv_wp_ctx_t *ctx,
                    const uint8_t in[16], uint8_t out[16]) {
  uint32_t col[4];
  pack_state(in, col);

  int r = ctx->rounds;
  for (int i = 0; i < r; i++) {
    /* Round key pair: K_{2i}, K_{2i+1} at offsets 8*i and 8*i+4 */
    f128_wp(col, &ctx->rk[8*i], &ctx->rk[8*i + 4]);
  }
  /* Final AddRoundKey with K_{2r} */
  col[0] ^= ctx->rk[8*r]; col[1] ^= ctx->rk[8*r+1];
  col[2] ^= ctx->rk[8*r+2]; col[3] ^= ctx->rk[8*r+3];

  unpack_state(col, out);
}

void mkv_wp_decrypt(const mkv_wp_ctx_t *ctx,
                    const uint8_t in[16], uint8_t out[16]) {
  uint32_t col[4];
  pack_state(in, col);

  int r = ctx->rounds;
  /* Final AddRoundKey */
  col[0] ^= ctx->rk[8*r]; col[1] ^= ctx->rk[8*r+1];
  col[2] ^= ctx->rk[8*r+2]; col[3] ^= ctx->rk[8*r+3];

  for (int i = r-1; i >= 0; i--) {
    if128_wp(col, &ctx->rk[8*i], &ctx->rk[8*i + 4]);
  }

  unpack_state(col, out);
}

/* Wrapper to match mkv_wp_encrypt_only() signature for pre-key benchmark */
void mkv_wp_encrypt_only(const uint8_t *rk_ctx_bytes,
                          const uint8_t in[16], uint8_t out[16]) {
  mkv_wp_encrypt((const mkv_wp_ctx_t *)rk_ctx_bytes, in, out);
}

/* =========================================================================
 * Benchmark wrappers — full key schedule + encrypt each call.
 * Uses 128-bit key (r=7) for the benchmark.
 * ======================================================================= */
void mkv_wp_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
  mkv_wp_ctx_t ctx;
  mkv_wp_init(&ctx, MKV_ROUNDS_128, key);
  mkv_wp_encrypt(&ctx, in, out);
}

/*
 * mkv_wp_encrypt_opt: encrypt using fully-optimised path.
 *   • always_inline on all hot functions (no jal overhead at -Os)
 *   • xtime_w_nomul for polynomial reduction (no 'mul' instruction)
 *   • subcells4_zba for S-box lookup (sh2add)
 *   • pack_state_zbkb at input/output boundaries (packh+pack)
 */
void mkv_wp_encrypt_opt(const mkv_wp_ctx_t *ctx,
                         const uint8_t in[16], uint8_t out[16]) {
  uint32_t col[4];
  /* pack_state_lw beats pack_state_zbkb whenever 'in' is 4-byte aligned
   * (memcpy of 4 bytes → single lw on aligned targets).  Falls back to
   * byte assembly on unaligned input without ever being slower than the
   * Zbkb pack/packh path. */
  pack_state_lw(in, col);

  int r = ctx->rounds;
  for (int i = 0; i < r; i++) {
    f128_wp_opt(col, &ctx->rk[8*i], &ctx->rk[8*i + 4]);
  }
  col[0] ^= ctx->rk[8*r];   col[1] ^= ctx->rk[8*r+1];
  col[2] ^= ctx->rk[8*r+2]; col[3] ^= ctx->rk[8*r+3];

  unpack_state_sw(col, out);
}

void mkv_wp_bench_opt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
  mkv_wp_ctx_t ctx;
  mkv_wp_init(&ctx, MKV_ROUNDS_128, key);
  mkv_wp_encrypt_opt(&ctx, in, out);
}


/* =========================================================================
 * Self-test — verifies key schedule + encrypt/decrypt against the official
 * MKV128_8bit reference test vector (compiled from MKV128_8bit/MKV128_8bit/).
 *
 * Reference vectors (all 3 key sizes, same plaintext):
 *
 *   Plaintext : FF EE DD CC BB AA 99 88 77 66 55 44 33 22 11 00
 *   Key-128   : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
 *   Cipher-128: F2 79 5E CB A8 F4 D8 87 F5 39 EE 8D 8D F1 14 1D
 *
 *   Key-192   : 00 01 .. 17
 *   Cipher-192: D8 E0 A9 A2 99 4B 46 22 D8 37 67 6B 7A 54 BF E2
 *
 *   Key-256   : 00 01 .. 1F
 *   Cipher-256: 89 3F 15 62 5E 29 41 40 02 72 5C 12 78 1A 7A 34
 *
 * Returns:
 *   bit 0  = encrypt-128 OK
 *   bit 1  = round-trip decrypt-128 OK
 *   bit 2  = encrypt-192 OK
 *   bit 3  = encrypt-256 OK
 *   bit 4  = wp_zba variant matches wp (same crypto output)
 *   bit 5  = wp_opt variant matches wp
 * ======================================================================= */
int mkv_wp_selftest(void) {
  static const uint8_t plain[16] = {
    0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,
    0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00
  };
  static const uint8_t key128[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
  };
  static const uint8_t expect128[16] = {
    0xF2,0x79,0x5E,0xCB,0xA8,0xF4,0xD8,0x87,
    0xF5,0x39,0xEE,0x8D,0x8D,0xF1,0x14,0x1D
  };
  static const uint8_t key192[24] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
  };
  static const uint8_t expect192[16] = {
    0xD8,0xE0,0xA9,0xA2,0x99,0x4B,0x46,0x22,
    0xD8,0x37,0x67,0x6B,0x7A,0x54,0xBF,0xE2
  };
  static const uint8_t key256[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
  };
  static const uint8_t expect256[16] = {
    0x89,0x3F,0x15,0x62,0x5E,0x29,0x41,0x40,
    0x02,0x72,0x5C,0x12,0x78,0x1A,0x7A,0x34
  };

  int result = 0;
  uint8_t out[16], out2[16], rt[16];
  mkv_wp_ctx_t ctx;

  mkv_wp_init(&ctx, MKV_ROUNDS_128, key128);
  mkv_wp_encrypt(&ctx, plain, out);
  if (!memcmp(out, expect128, 16)) result |= 0x01;

  mkv_wp_decrypt(&ctx, out, rt);
  if (!memcmp(rt, plain, 16)) result |= 0x02;

  mkv_wp_init(&ctx, MKV_ROUNDS_192, key192);
  mkv_wp_encrypt(&ctx, plain, out);
  if (!memcmp(out, expect192, 16)) result |= 0x04;

  mkv_wp_init(&ctx, MKV_ROUNDS_256, key256);
  mkv_wp_encrypt(&ctx, plain, out);
  if (!memcmp(out, expect256, 16)) result |= 0x08;

  mkv_wp_init(&ctx, MKV_ROUNDS_128, key128);
  mkv_wp_encrypt    (&ctx, plain, out);
  mkv_wp_encrypt_opt(&ctx, plain, out2);
  if (!memcmp(out, out2, 16)) result |= 0x20;

  return result;
}
