/*
 * AES-128 T-table implementation — maximum bitmanip optimization.
 *
 * Strategy: combine SubBytes + ShiftRows + MixColumns into T-table lookups.
 * Use 1 T-table (1 KB) + rori for rotation = saves 3 KB vs classic 4-table.
 *
 * Per round (9 mid-rounds):
 *   4 table lookups (sh2add for indexing) + 3 rori + 4 XOR + byte extraction
 *   = ~20 instructions per column × 4 columns = ~80 instructions per round
 *
 * vs AES-WP (current):
 *   16 S-box lookups + ShiftRows + 4 MixCol (each: xtime + 3 ror) + 4 XOR
 *   = ~60 instructions per column × 4 columns = ~240 instructions per round
 *
 * Expected: ~3× faster than AES-WP.
 */

#include <stdint.h>
#include <string.h>
#include "aes.h"       /* reuse AES_init_ctx key schedule */
#include "aes_ttable.h"

/* AES S-box (same as tiny-AES-c) */
static const uint8_t tt_sbox[256] = {
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

/*
 * ror32: GCC+Zbb emits 'rori' (1 cycle); without Zbb: srl+sll+or (3 cycles).
 * Called 108 times per block (3 per column × 4 cols × 9 rounds).
 */
static inline uint32_t ror32(uint32_t x, int n) {
  return (x >> n) | (x << (32 - n));
}

/*
 * xtime: GF(2^8) multiply by 2 (for T-table generation only, not in hot path).
 */
static inline uint8_t xtime(uint8_t b) {
  return (b << 1) ^ ((b & 0x80) ? 0x1b : 0x00);
}

/*
 * T-table: Te[i] = MixColumns column 0 applied to Sbox[i].
 *
 * MixColumns matrix:
 *   [2 3 1 1]
 *   [1 2 3 1]
 *   [1 1 2 3]
 *   [3 1 1 2]
 *
 * Column 0 contribution: [2·s, 1·s, 1·s, 3·s] (row0 to row3, LSB to MSB)
 *
 * Little-endian uint32_t:
 *   Te[i] = (3·s << 24) | (1·s << 16) | (1·s << 8) | 2·s
 *
 * Other columns obtained via rori:
 *   Te1 = rori(Te, 24)  (column 1: [3·s, 2·s, 1·s, 1·s])
 *   Te2 = rori(Te, 16)  (column 2: [1·s, 3·s, 2·s, 1·s])
 *   Te3 = rori(Te,  8)  (column 3: [1·s, 1·s, 3·s, 2·s])
 *
 * Table size: 256 × 4 = 1024 bytes in .rodata.
 * GCC+Zba: Te[index] compiles to 'sh2add index, Te_base; lw' (2 insn)
 *          Without Zba: 'slli index,2; add; lw' (3 insn)
 */
static uint32_t Te[256];

void aes_ttable_init(void) {
  for (int i = 0; i < 256; i++) {
    uint8_t s  = tt_sbox[i];
    uint8_t s2 = xtime(s);      /* ×2 */
    uint8_t s3 = s2 ^ s;        /* ×3 */
    /* Te[i] = [2s, 1s, 1s, 3s] little-endian (row0 at LSB) */
    Te[i] = (uint32_t)s2
          | ((uint32_t)s  <<  8)
          | ((uint32_t)s  << 16)
          | ((uint32_t)s3 << 24);
  }
}

/*
 * Encrypt one block with pre-expanded round keys.
 *
 * State: 4 columns, each uint32_t, little-endian.
 *   s[c] = in[c*4] | in[c*4+1]<<8 | in[c*4+2]<<16 | in[c*4+3]<<24
 *   byte 0 (LSB) = row 0, byte 3 (MSB) = row 3
 *
 * ShiftRows: row i shifted left by i.
 *   Output col 0: row0 from s0, row1 from s1, row2 from s2, row3 from s3
 *   Output col 1: row0 from s1, row1 from s2, row2 from s3, row3 from s0
 *   Output col 2: row0 from s2, row1 from s3, row2 from s0, row3 from s1
 *   Output col 3: row0 from s3, row1 from s0, row2 from s1, row3 from s2
 *
 * Combined SubBytes + ShiftRows + MixColumns via T-table:
 *   t0 = Te[s0&0xFF] ^ rori(Te[(s1>>8)&0xFF],24) ^ rori(Te[(s2>>16)&0xFF],16) ^ rori(Te[s3>>24],8) ^ rk[0]
 *   t1 = Te[s1&0xFF] ^ rori(Te[(s2>>8)&0xFF],24) ^ rori(Te[(s3>>16)&0xFF],16) ^ rori(Te[s0>>24],8) ^ rk[1]
 *   t2 = Te[s2&0xFF] ^ rori(Te[(s3>>8)&0xFF],24) ^ rori(Te[(s0>>16)&0xFF],16) ^ rori(Te[s1>>24],8) ^ rk[2]
 *   t3 = Te[s3&0xFF] ^ rori(Te[(s0>>8)&0xFF],24) ^ rori(Te[(s1>>16)&0xFF],16) ^ rori(Te[s2>>24],8) ^ rk[3]
 */
void aes_ttable_encrypt_rk(const uint32_t *rk,
                            const uint8_t in[16],
                            uint8_t out[16]) {
  /* Load state (little-endian, direct word access) */
  uint32_t s0, s1, s2, s3;
  memcpy(&s0, in +  0, 4);
  memcpy(&s1, in +  4, 4);
  memcpy(&s2, in +  8, 4);
  memcpy(&s3, in + 12, 4);

  /* Round 0: AddRoundKey */
  s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];

  /* Rounds 1-9: T-table lookup + rori */
  for (int r = 1; r <= 9; r++) {
    uint32_t t0 = Te[s0 & 0xFFu]
                ^ ror32(Te[(s1 >>  8) & 0xFFu], 24)
                ^ ror32(Te[(s2 >> 16) & 0xFFu], 16)
                ^ ror32(Te[s3 >> 24          ],  8)
                ^ rk[r * 4    ];
    uint32_t t1 = Te[s1 & 0xFFu]
                ^ ror32(Te[(s2 >>  8) & 0xFFu], 24)
                ^ ror32(Te[(s3 >> 16) & 0xFFu], 16)
                ^ ror32(Te[s0 >> 24          ],  8)
                ^ rk[r * 4 + 1];
    uint32_t t2 = Te[s2 & 0xFFu]
                ^ ror32(Te[(s3 >>  8) & 0xFFu], 24)
                ^ ror32(Te[(s0 >> 16) & 0xFFu], 16)
                ^ ror32(Te[s1 >> 24          ],  8)
                ^ rk[r * 4 + 2];
    uint32_t t3 = Te[s3 & 0xFFu]
                ^ ror32(Te[(s0 >>  8) & 0xFFu], 24)
                ^ ror32(Te[(s1 >> 16) & 0xFFu], 16)
                ^ ror32(Te[s2 >> 24          ],  8)
                ^ rk[r * 4 + 3];
    s0 = t0; s1 = t1; s2 = t2; s3 = t3;
  }

  /* Round 10: SubBytes + ShiftRows + AddRoundKey (no MixColumns) */
  uint32_t t0 = ((uint32_t)tt_sbox[s0 & 0xFFu])
              | ((uint32_t)tt_sbox[(s1 >>  8) & 0xFFu] <<  8)
              | ((uint32_t)tt_sbox[(s2 >> 16) & 0xFFu] << 16)
              | ((uint32_t)tt_sbox[s3 >> 24          ] << 24);
  t0 ^= rk[40];

  uint32_t t1 = ((uint32_t)tt_sbox[s1 & 0xFFu])
              | ((uint32_t)tt_sbox[(s2 >>  8) & 0xFFu] <<  8)
              | ((uint32_t)tt_sbox[(s3 >> 16) & 0xFFu] << 16)
              | ((uint32_t)tt_sbox[s0 >> 24          ] << 24);
  t1 ^= rk[41];

  uint32_t t2 = ((uint32_t)tt_sbox[s2 & 0xFFu])
              | ((uint32_t)tt_sbox[(s3 >>  8) & 0xFFu] <<  8)
              | ((uint32_t)tt_sbox[(s0 >> 16) & 0xFFu] << 16)
              | ((uint32_t)tt_sbox[s1 >> 24          ] << 24);
  t2 ^= rk[42];

  uint32_t t3 = ((uint32_t)tt_sbox[s3 & 0xFFu])
              | ((uint32_t)tt_sbox[(s0 >>  8) & 0xFFu] <<  8)
              | ((uint32_t)tt_sbox[(s1 >> 16) & 0xFFu] << 16)
              | ((uint32_t)tt_sbox[s2 >> 24          ] << 24);
  t3 ^= rk[43];

  /* Store result */
  memcpy(out +  0, &t0, 4);
  memcpy(out +  4, &t1, 4);
  memcpy(out +  8, &t2, 4);
  memcpy(out + 12, &t3, 4);
}

/* Benchmark wrapper: cached key, encrypt-only */
static struct AES_ctx g_tt_ctx;
static uint8_t g_tt_k[16];
static int g_tt_rdy = 0;

void aes_ttable_bench(const uint8_t key[16],
                      const uint8_t in[16],
                      uint8_t out[16]) {
  if (!g_tt_rdy || memcmp(key, g_tt_k, 16)) {
    AES_init_ctx(&g_tt_ctx, key);
    memcpy(g_tt_k, key, 16);
    g_tt_rdy = 1;
  }
  aes_ttable_encrypt_rk((const uint32_t *)g_tt_ctx.RoundKey, in, out);
}
