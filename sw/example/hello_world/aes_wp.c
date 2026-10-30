/*
 * Word-Parallel AES-128 ECB — designed to show RISC-V Zbb (Bitmanip) benefit.
 *
 * State representation
 * --------------------
 * AES state is 4 columns × 4 rows. We pack each column into one uint32_t:
 *   s[col] = row0 | (row1 << 8) | (row2 << 16) | (row3 << 24)
 * This matches tiny-AES-c's state[col][row] byte layout on little-endian RISC-V.
 *
 * Two operations that directly benefit from Zbb
 * ----------------------------------------------
 * 1. ror32(x, n)  — rotate right 32-bit word
 *      Without Zbb:  srl + sll + or  = 3 instructions
 *      With    Zbb:  rori             = 1 instruction  (saves 2 per call)
 *    Used in MixColumns (3 rotations × 4 columns × 9 rounds = 108 calls → saves 216 insns)
 *
 * 2. x & ~0x80808080u  — clear MSB of each byte (in xtime_word)
 *      Without Zbb:  lui (load ~mask) + and = 2 instructions
 *      With    Zbb:  andn              = 1 instruction  (saves 1 per call)
 *    Used in xtime_word (1 call × 4 columns × 10 rounds = 40 calls → saves 40 insns)
 *
 * Total saving: ~256 extra instructions eliminated per block with Zbb.
 * SubBytes still does 16 S-box memory loads per round — Zbb cannot help that part.
 *
 * GCC automatically emits 'rori' and 'andn' when recognizing the patterns,
 * provided the -march includes 'zbb'.
 */

#include <stdint.h>
#include <string.h>
#include "aes.h"      // AES_ctx, AES_init_ctx — reuse key schedule
#include "aes_wp.h"

/* -------------------------------------------------------------------------
 * AES S-box (same 256-byte table as tiny-AES-c)
 * ---------------------------------------------------------------------- */
static const uint8_t wp_sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* -------------------------------------------------------------------------
 * ror32: rotate right by n bits.
 *
 * GCC pattern recognition:
 *   -march includes 'zbb'  → emits 'rori' (1 cycle)
 *   otherwise              → emits 'srl' + 'sll' + 'or' (3 cycles)
 *
 * This is the PRIMARY instruction where Zbb helps in this implementation.
 * Called 3 times per MixCol × 4 columns × 9 mid-rounds = 108 times per block.
 * ---------------------------------------------------------------------- */
static inline uint32_t ror32(uint32_t x, int n) {
  return (x >> n) | (x << (32 - n));
}

/* -------------------------------------------------------------------------
 * SubWord: apply AES S-box to all 4 bytes of a 32-bit column word.
 * Still memory-bound (4 table lookups) — Zbb does not help here.
 * ---------------------------------------------------------------------- */
static inline uint32_t SubWord(uint32_t w) {
  return (uint32_t)wp_sbox[ w        & 0xFF]
       | ((uint32_t)wp_sbox[(w >>  8) & 0xFF] <<  8)
       | ((uint32_t)wp_sbox[(w >> 16) & 0xFF] << 16)
       | ((uint32_t)wp_sbox[(w >> 24)        ] << 24);
}

/* -------------------------------------------------------------------------
 * xtime_word: multiply each of the 4 bytes by 2 in GF(2^8) simultaneously.
 *
 *   For each byte b:
 *     if (b & 0x80): xtime(b) = (b << 1) ^ 0x1b
 *     else:          xtime(b) = (b << 1)
 *
 * Word-level implementation:
 *   lo  = x & ~0x80808080   → clear bit7 of each byte before shifting
 *                              GCC+Zbb: 'andn lo, x, mask' (1 instr)
 *                              Without: 'lui + and' (2 instr)
 *   t   = (x >> 7) & 0x01010101  → 0x01 per byte where bit7 was set
 *   poly = t * 0x1b         → 0x1b per byte where reduction needed
 *                              (safe: t[byte] ≤ 0x01, so 0x1b*1=0x1b < 256, no carry)
 * ---------------------------------------------------------------------- */
static inline uint32_t xtime_word(uint32_t x) {
  /* GCC+Zbb: the '& ~mask' pattern compiles to 'andn' (1 instr, saves 1) */
  return ((x & ~0x80808080u) << 1)
       ^ (((x >> 7) & 0x01010101u) * 0x1bu);
}

/* -------------------------------------------------------------------------
 * MixCol: AES MixColumns for one 32-bit column word w.
 *
 * Word w packs 4 bytes: w = [a0, a1, a2, a3] at bits [7:0, 15:8, 23:16, 31:24].
 *
 * AES MixColumns matrix (FIPS 197 Eq. 4.12):
 *   [a0']   [2 3 1 1] [a0]
 *   [a1'] = [1 2 3 1] [a1]   (all operations in GF(2^8))
 *   [a2']   [1 1 2 3] [a2]
 *   [a3']   [3 1 1 2] [a3]
 *
 * Expanded per byte:
 *   a0' = 2*a0 ^ 3*a1 ^ a2  ^ a3
 *   a1' = a0  ^ 2*a1 ^ 3*a2 ^ a3
 *   a2' = a0  ^ a1  ^ 2*a2  ^ 3*a3
 *   a3' = 3*a0 ^ a1 ^ a2   ^ 2*a3
 *
 * Let t = xtime_word(w)  → t[i] = 2*a[i]
 *     r = t ^ w          → r[i] = 3*a[i]  (since 3x = 2x ^ x)
 * Then:
 *   result[i] = t[i] ^ r[i+1] ^ w[i+2] ^ w[i+3]
 *
 * In 32-bit word form:
 *   result = t ^ ror(r, 8) ^ ror(w, 16) ^ ror(w, 24)
 *
 * Proof for byte 0: t[0] ^ r[1] ^ w[2] ^ w[3]
 *   = 2*a0 ^ (2*a1^a1) ^ a2 ^ a3 = 2*a0 ^ 3*a1 ^ a2 ^ a3  ✓
 *
 * KEY Zbb benefit: 3 ror32 calls per column.
 * Total: 3 ror × 4 col × 9 rounds = 108 rotations per block.
 * Savings: 108 × 2 instructions = 216 instructions saved per block with Zbb.
 * ---------------------------------------------------------------------- */
static inline uint32_t MixCol(uint32_t w) {
  uint32_t t = xtime_word(w);   /* t[i] = 2·a[i]               */
  uint32_t r = t ^ w;           /* r[i] = 3·a[i]               */
  return t
       ^ ror32(r,  8)           /* GCC+Zbb: rori (1 instr)     */
       ^ ror32(w, 16)           /* GCC no-Zbb: srl+sll+or (3)  */
       ^ ror32(w, 24);
}

/* -------------------------------------------------------------------------
 * ShiftRows on word-parallel state.
 *
 * After ShiftRows, column c gets:
 *   bits  7: 0 (row 0) from col  c        (no shift)
 *   bits 15: 8 (row 1) from col (c+1)%4   (shift left by 1)
 *   bits 23:16 (row 2) from col (c+2)%4   (shift left by 2)
 *   bits 31:24 (row 3) from col (c+3)%4   (shift left by 3)
 * ---------------------------------------------------------------------- */
static inline void ShiftRows(uint32_t s[4]) {
  uint32_t t[4];
  for (int c = 0; c < 4; c++) {
    t[c] = ( s[ c        ]        & 0x000000FFu)
         | ( s[(c + 1) & 3]       & 0x0000FF00u)
         | ( s[(c + 2) & 3]       & 0x00FF0000u)
         | ( s[(c + 3) & 3]       & 0xFF000000u);
  }
  s[0] = t[0]; s[1] = t[1]; s[2] = t[2]; s[3] = t[3];
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */
/*
 * Encrypt-only: uses pre-expanded round keys (44 uint32_t = 176 bytes).
 * Call AES_init_ctx() once, then this for each block.
 */
void aes128_ecb_encrypt_wp_rk(const uint32_t *rk,
                               const uint8_t in[16],
                               uint8_t out[16]) {
  /* Load state: s[col] = row0 | row1<<8 | row2<<16 | row3<<24 */
  uint32_t s[4];
  for (int c = 0; c < 4; c++) {
    s[c] = (uint32_t)in[c * 4    ]
         | ((uint32_t)in[c * 4 + 1] <<  8)
         | ((uint32_t)in[c * 4 + 2] << 16)
         | ((uint32_t)in[c * 4 + 3] << 24);
  }

  /* Round 0: AddRoundKey only */
  s[0] ^= rk[0]; s[1] ^= rk[1]; s[2] ^= rk[2]; s[3] ^= rk[3];

  /* Rounds 1-9: SubBytes + ShiftRows + MixColumns + AddRoundKey */
  for (int r = 1; r <= 9; r++) {
    s[0] = SubWord(s[0]);
    s[1] = SubWord(s[1]);
    s[2] = SubWord(s[2]);
    s[3] = SubWord(s[3]);
    ShiftRows(s);
    s[0] = MixCol(s[0]);
    s[1] = MixCol(s[1]);
    s[2] = MixCol(s[2]);
    s[3] = MixCol(s[3]);
    s[0] ^= rk[r * 4    ];
    s[1] ^= rk[r * 4 + 1];
    s[2] ^= rk[r * 4 + 2];
    s[3] ^= rk[r * 4 + 3];
  }

  /* Round 10: SubBytes + ShiftRows + AddRoundKey (no MixColumns) */
  s[0] = SubWord(s[0]);
  s[1] = SubWord(s[1]);
  s[2] = SubWord(s[2]);
  s[3] = SubWord(s[3]);
  ShiftRows(s);
  s[0] ^= rk[40]; s[1] ^= rk[41]; s[2] ^= rk[42]; s[3] ^= rk[43];

  /* Store result */
  for (int c = 0; c < 4; c++) {
    out[c * 4    ] =  s[c]        & 0xFFu;
    out[c * 4 + 1] = (s[c] >>  8) & 0xFFu;
    out[c * 4 + 2] = (s[c] >> 16) & 0xFFu;
    out[c * 4 + 3] = (s[c] >> 24) & 0xFFu;
  }
}

void aes128_ecb_encrypt_wp(const uint8_t key[16],
                            const uint8_t in[16],
                            uint8_t out[16]) {
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, key);
  aes128_ecb_encrypt_wp_rk((const uint32_t *)ctx.RoundKey, in, out);
}

/* =========================================================================
 * Zba (sh2add) demonstration variant
 * =========================================================================
 *
 * WHY wp_sbox is uint8_t and Zba cannot help it:
 *   wp_sbox    is uint8_t[256].
 *   sbox[i] address = base + i*1  →  'add' (no scaling), GCC emits 'lbu'.
 *   Zba sh2add computes base + i*4, NOT base + i*1 → useless for uint8_t.
 *
 * WHY wp_sbox_w32 lets Zba help:
 *   wp_sbox_w32 is uint32_t[256], same values stored as 32-bit words.
 *   sbox_w32[i] address = base + i*4  →  GCC+Zba emits 'sh2add' + 'lw'.
 *   Without Zba: 'slli i,i,2; add addr,base,i; lw' (3 instructions).
 *   With    Zba: 'sh2add addr,i,base; lw'          (2 instructions).
 *   Saves: 1 instruction × 4 lookups × 4 cols × 10 rounds = 160 insns/block.
 *
 * The table is 1 KB larger (256×4 vs 256×1), stored in IMEM (.rodata).
 * The loaded uint32_t carries the S-box byte in bits 7:0 — identical value,
 * just padded to 32 bits for word-aligned addressing.
 * ========================================================================= */
static const uint32_t wp_sbox_w32[256] = {
  0x63u,0x7cu,0x77u,0x7bu,0xf2u,0x6bu,0x6fu,0xc5u,
  0x30u,0x01u,0x67u,0x2bu,0xfeu,0xd7u,0xabu,0x76u,
  0xcau,0x82u,0xc9u,0x7du,0xfau,0x59u,0x47u,0xf0u,
  0xadu,0xd4u,0xa2u,0xafu,0x9cu,0xa4u,0x72u,0xc0u,
  0xb7u,0xfdu,0x93u,0x26u,0x36u,0x3fu,0xf7u,0xccu,
  0x34u,0xa5u,0xe5u,0xf1u,0x71u,0xd8u,0x31u,0x15u,
  0x04u,0xc7u,0x23u,0xc3u,0x18u,0x96u,0x05u,0x9au,
  0x07u,0x12u,0x80u,0xe2u,0xebu,0x27u,0xb2u,0x75u,
  0x09u,0x83u,0x2cu,0x1au,0x1bu,0x6eu,0x5au,0xa0u,
  0x52u,0x3bu,0xd6u,0xb3u,0x29u,0xe3u,0x2fu,0x84u,
  0x53u,0xd1u,0x00u,0xedu,0x20u,0xfcu,0xb1u,0x5bu,
  0x6au,0xcbu,0xbeu,0x39u,0x4au,0x4cu,0x58u,0xcfu,
  0xd0u,0xefu,0xaau,0xfbu,0x43u,0x4du,0x33u,0x85u,
  0x45u,0xf9u,0x02u,0x7fu,0x50u,0x3cu,0x9fu,0xa8u,
  0x51u,0xa3u,0x40u,0x8fu,0x92u,0x9du,0x38u,0xf5u,
  0xbcu,0xb6u,0xdau,0x21u,0x10u,0xffu,0xf3u,0xd2u,
  0xcdu,0x0cu,0x13u,0xecu,0x5fu,0x97u,0x44u,0x17u,
  0xc4u,0xa7u,0x7eu,0x3du,0x64u,0x5du,0x19u,0x73u,
  0x60u,0x81u,0x4fu,0xdcu,0x22u,0x2au,0x90u,0x88u,
  0x46u,0xeeu,0xb8u,0x14u,0xdeu,0x5eu,0x0bu,0xdbu,
  0xe0u,0x32u,0x3au,0x0au,0x49u,0x06u,0x24u,0x5cu,
  0xc2u,0xd3u,0xacu,0x62u,0x91u,0x95u,0xe4u,0x79u,
  0xe7u,0xc8u,0x37u,0x6du,0x8du,0xd5u,0x4eu,0xa9u,
  0x6cu,0x56u,0xf4u,0xeau,0x65u,0x7au,0xaeu,0x08u,
  0xbau,0x78u,0x25u,0x2eu,0x1cu,0xa6u,0xb4u,0xc6u,
  0xe8u,0xddu,0x74u,0x1fu,0x4bu,0xbdu,0x8bu,0x8au,
  0x70u,0x3eu,0xb5u,0x66u,0x48u,0x03u,0xf6u,0x0eu,
  0x61u,0x35u,0x57u,0xb9u,0x86u,0xc1u,0x1du,0x9eu,
  0xe1u,0xf8u,0x98u,0x11u,0x69u,0xd9u,0x8eu,0x94u,
  0x9bu,0x1eu,0x87u,0xe9u,0xceu,0x55u,0x28u,0xdfu,
  0x8cu,0xa1u,0x89u,0x0du,0xbfu,0xe6u,0x42u,0x68u,
  0x41u,0x99u,0x2du,0x0fu,0xb0u,0x54u,0xbbu,0x16u
};

/*
 * SubWord using word-sized S-box.
 * GCC+Zba emits 'sh2add addr, byte_idx, table_base' for each of the 4 lookups.
 * Without Zba: 'slli byte_idx, byte_idx, 2; add addr, base, byte_idx' (2 insns).
 */
static inline uint32_t SubWord_w32(uint32_t w) {
  return  (uint32_t)wp_sbox_w32[ w        & 0xFFu]
       | ((uint32_t)wp_sbox_w32[(w >>  8) & 0xFFu] <<  8)
       | ((uint32_t)wp_sbox_w32[(w >> 16) & 0xFFu] << 16)
       | ((uint32_t)wp_sbox_w32[(w >> 24)         ] << 24);
}

/*
 * AES-128 ECB encrypt, Zba variant.
 * Functionally identical to aes128_ecb_encrypt_wp().
 * Only difference: SubBytes uses SubWord_w32() (uint32_t table, sh2add)
 * instead of SubWord() (uint8_t table, plain add/lbu).
 *
 * Expected speedup over [2]: saves 160 address-scale instructions/block.
 * Actual measured speedup depends on pipeline depth — NEORV32 is in-order
 * so the extra slli in the critical path costs a real cycle per lookup.
 */
void aes128_ecb_encrypt_wp_zba(const uint8_t key[16],
                                const uint8_t in[16],
                                uint8_t out[16]) {
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, key);
  const uint32_t *rk = (const uint32_t *)ctx.RoundKey;

  uint32_t s[4];
  for (int c = 0; c < 4; c++) {
    s[c] = (uint32_t)in[c * 4    ]
         | ((uint32_t)in[c * 4 + 1] <<  8)
         | ((uint32_t)in[c * 4 + 2] << 16)
         | ((uint32_t)in[c * 4 + 3] << 24);
  }

  s[0] ^= rk[0]; s[1] ^= rk[1]; s[2] ^= rk[2]; s[3] ^= rk[3];

  for (int r = 1; r <= 9; r++) {
    /* SubBytes: GCC+Zba → 'sh2add addr, byte_idx, base' per lookup */
    s[0] = SubWord_w32(s[0]);
    s[1] = SubWord_w32(s[1]);
    s[2] = SubWord_w32(s[2]);
    s[3] = SubWord_w32(s[3]);
    ShiftRows(s);
    s[0] = MixCol(s[0]);
    s[1] = MixCol(s[1]);
    s[2] = MixCol(s[2]);
    s[3] = MixCol(s[3]);
    s[0] ^= rk[r * 4    ];
    s[1] ^= rk[r * 4 + 1];
    s[2] ^= rk[r * 4 + 2];
    s[3] ^= rk[r * 4 + 3];
  }

  /* Round 10: no MixColumns */
  s[0] = SubWord_w32(s[0]);
  s[1] = SubWord_w32(s[1]);
  s[2] = SubWord_w32(s[2]);
  s[3] = SubWord_w32(s[3]);
  ShiftRows(s);
  s[0] ^= rk[40]; s[1] ^= rk[41]; s[2] ^= rk[42]; s[3] ^= rk[43];

  for (int c = 0; c < 4; c++) {
    out[c * 4    ] =  s[c]        & 0xFFu;
    out[c * 4 + 1] = (s[c] >>  8) & 0xFFu;
    out[c * 4 + 2] = (s[c] >> 16) & 0xFFu;
    out[c * 4 + 3] = (s[c] >> 24) & 0xFFu;
  }
}
