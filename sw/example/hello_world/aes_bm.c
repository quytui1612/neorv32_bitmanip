/*
 * AES-BM: AES-128 tối ưu cho RISC-V Bitmanip.
 *
 * Khác hoàn toàn tiny-AES-c (byte-oriented loop):
 *   1. Word-packed state (4×uint32_t, mỗi cột = 1 word)
 *   2. MixColumns dùng rori (Zbb) — 1 instr thay vì srli+slli+or
 *   3. xtime_word dùng andn (Zbb) — 1 instr thay vì lui+and
 *   4. ShiftRows word-level — mask+or thay vì byte swap
 *   5. AddRoundKey: 4 XOR thay vì 16 XOR
 *   6. Fully unrolled 10 rounds — không loop overhead
 *   7. Cached key — không key schedule trong benchmark loop
 *
 * Cấu trúc baseline (tiny-AES-c):
 *   - State = uint8_t[4][4] — xử lý từng byte
 *   - MixColumns = 4× (xtime byte + XOR) mỗi cột
 *   - ShiftRows = byte shuffle
 *   - AddRoundKey = 16 XOR
 *
 * Speedup đến từ: rori (216 instr tiết kiệm) + andn (40 instr) + word ops (132 instr)
 */

#include <stdint.h>
#include <string.h>
#include "aes.h"      /* reuse AES_init_ctx key schedule */
#include "aes_bm.h"

/* Same S-box */
static const uint8_t bm_sbox[256] = {
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

/* ror32: GCC+Zbb → rori (1 instr); without → srli+slli+or (3 instr) */
static inline uint32_t ror32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

/* SubWord: 4 byte S-box lookups packed into one word */
static inline uint32_t SubWord(uint32_t w) {
    return  (uint32_t)bm_sbox[(uint8_t)(w)]
         | ((uint32_t)bm_sbox[(uint8_t)(w >>  8)] <<  8)
         | ((uint32_t)bm_sbox[(uint8_t)(w >> 16)] << 16)
         | ((uint32_t)bm_sbox[(uint8_t)(w >> 24)] << 24);
}

/* xtime_word: multiply each byte by 2 in GF(2^8) simultaneously.
 * GCC+Zbb: andn for (x & ~0x80808080) = 1 instr; without: lui+and = 2 instr */
static inline uint32_t xtime_word(uint32_t x) {
    return ((x & ~0x80808080u) << 1)
         ^ (((x >> 7) & 0x01010101u) * 0x1bu);
}

/* MixCol: AES MixColumns for one column word.
 * result = t ^ ror(r,8) ^ ror(w,16) ^ ror(w,24)
 * 3× rori per column with Zbb; 3× (srli+slli+or) without */
static inline uint32_t MixCol(uint32_t w) {
    uint32_t t = xtime_word(w);
    uint32_t r = t ^ w;
    return t ^ ror32(r, 8) ^ ror32(w, 16) ^ ror32(w, 24);
}

/* ShiftRows on word-parallel state */
static inline void ShiftRows(uint32_t s[4]) {
    uint32_t t[4];
    t[0] = (s[0] & 0x000000FFu) | (s[1] & 0x0000FF00u) | (s[2] & 0x00FF0000u) | (s[3] & 0xFF000000u);
    t[1] = (s[1] & 0x000000FFu) | (s[2] & 0x0000FF00u) | (s[3] & 0x00FF0000u) | (s[0] & 0xFF000000u);
    t[2] = (s[2] & 0x000000FFu) | (s[3] & 0x0000FF00u) | (s[0] & 0x00FF0000u) | (s[1] & 0xFF000000u);
    t[3] = (s[3] & 0x000000FFu) | (s[0] & 0x0000FF00u) | (s[1] & 0x00FF0000u) | (s[2] & 0xFF000000u);
    s[0]=t[0]; s[1]=t[1]; s[2]=t[2]; s[3]=t[3];
}

/* Cached round keys (word-aligned) */
static uint32_t g_rk[44];
static uint8_t g_key[16];
static int g_ready = 0;

static void ensure_key(const uint8_t key[16]) {
    if (!g_ready || memcmp(key, g_key, 16)) {
        struct AES_ctx ctx;
        AES_init_ctx(&ctx, key);
        memcpy(g_rk, ctx.RoundKey, sizeof(g_rk));
        memcpy(g_key, key, 16);
        g_ready = 1;
    }
}

/* Fully optimized encrypt: word-parallel + unrolled */
void aes_bm_encrypt(const uint8_t in[16], uint8_t out[16]) {
    /* Load state as 4 column words */
    uint32_t s0 = *(const uint32_t *)(in)
                ^ g_rk[0];
    uint32_t s1 = *(const uint32_t *)(in + 4)
                ^ g_rk[1];
    uint32_t s2 = *(const uint32_t *)(in + 8)
                ^ g_rk[2];
    uint32_t s3 = *(const uint32_t *)(in + 12)
                ^ g_rk[3];

    /* Rounds 1-9: SubBytes + ShiftRows + MixColumns + AddRoundKey */
    /* Fully unrolled — each round inline */
#define ROUND(r) \
    s0 = SubWord(s0); s1 = SubWord(s1); s2 = SubWord(s2); s3 = SubWord(s3); \
    ShiftRows((uint32_t[]){s0,s1,s2,s3}); \
    { uint32_t t[4]={s0,s1,s2,s3}; ShiftRows(t); s0=t[0];s1=t[1];s2=t[2];s3=t[3]; } \
    s0 = MixCol(s0) ^ g_rk[(r)*4  ]; \
    s1 = MixCol(s1) ^ g_rk[(r)*4+1]; \
    s2 = MixCol(s2) ^ g_rk[(r)*4+2]; \
    s3 = MixCol(s3) ^ g_rk[(r)*4+3]

    /* Actually, ShiftRows needs all 4 words together. Let me do it properly. */
    /* Round 1 */
    s0=SubWord(s0); s1=SubWord(s1); s2=SubWord(s2); s3=SubWord(s3);
    { uint32_t t[4]={s0,s1,s2,s3}; ShiftRows(t); s0=t[0];s1=t[1];s2=t[2];s3=t[3]; }
    s0=MixCol(s0)^g_rk[4]; s1=MixCol(s1)^g_rk[5]; s2=MixCol(s2)^g_rk[6]; s3=MixCol(s3)^g_rk[7];
    /* Round 2 */
    s0=SubWord(s0); s1=SubWord(s1); s2=SubWord(s2); s3=SubWord(s3);
    { uint32_t t[4]={s0,s1,s2,s3}; ShiftRows(t); s0=t[0];s1=t[1];s2=t[2];s3=t[3]; }
    s0=MixCol(s0)^g_rk[8]; s1=MixCol(s1)^g_rk[9]; s2=MixCol(s2)^g_rk[10]; s3=MixCol(s3)^g_rk[11];
    /* Round 3 */
    s0=SubWord(s0); s1=SubWord(s1); s2=SubWord(s2); s3=SubWord(s3);
    { uint32_t t[4]={s0,s1,s2,s3}; ShiftRows(t); s0=t[0];s1=t[1];s2=t[2];s3=t[3]; }
    s0=MixCol(s0)^g_rk[12]; s1=MixCol(s1)^g_rk[13]; s2=MixCol(s2)^g_rk[14]; s3=MixCol(s3)^g_rk[15];
    /* Round 4 */
    s0=SubWord(s0); s1=SubWord(s1); s2=SubWord(s2); s3=SubWord(s3);
    { uint32_t t[4]={s0,s1,s2,s3}; ShiftRows(t); s0=t[0];s1=t[1];s2=t[2];s3=t[3]; }
    s0=MixCol(s0)^g_rk[16]; s1=MixCol(s1)^g_rk[17]; s2=MixCol(s2)^g_rk[18]; s3=MixCol(s3)^g_rk[19];
    /* Round 5 */
    s0=SubWord(s0); s1=SubWord(s1); s2=SubWord(s2); s3=SubWord(s3);
    { uint32_t t[4]={s0,s1,s2,s3}; ShiftRows(t); s0=t[0];s1=t[1];s2=t[2];s3=t[3]; }
    s0=MixCol(s0)^g_rk[20]; s1=MixCol(s1)^g_rk[21]; s2=MixCol(s2)^g_rk[22]; s3=MixCol(s3)^g_rk[23];
    /* Round 6 */
    s0=SubWord(s0); s1=SubWord(s1); s2=SubWord(s2); s3=SubWord(s3);
    { uint32_t t[4]={s0,s1,s2,s3}; ShiftRows(t); s0=t[0];s1=t[1];s2=t[2];s3=t[3]; }
    s0=MixCol(s0)^g_rk[24]; s1=MixCol(s1)^g_rk[25]; s2=MixCol(s2)^g_rk[26]; s3=MixCol(s3)^g_rk[27];
    /* Round 7 */
    s0=SubWord(s0); s1=SubWord(s1); s2=SubWord(s2); s3=SubWord(s3);
    { uint32_t t[4]={s0,s1,s2,s3}; ShiftRows(t); s0=t[0];s1=t[1];s2=t[2];s3=t[3]; }
    s0=MixCol(s0)^g_rk[28]; s1=MixCol(s1)^g_rk[29]; s2=MixCol(s2)^g_rk[30]; s3=MixCol(s3)^g_rk[31];
    /* Round 8 */
    s0=SubWord(s0); s1=SubWord(s1); s2=SubWord(s2); s3=SubWord(s3);
    { uint32_t t[4]={s0,s1,s2,s3}; ShiftRows(t); s0=t[0];s1=t[1];s2=t[2];s3=t[3]; }
    s0=MixCol(s0)^g_rk[32]; s1=MixCol(s1)^g_rk[33]; s2=MixCol(s2)^g_rk[34]; s3=MixCol(s3)^g_rk[35];
    /* Round 9 */
    s0=SubWord(s0); s1=SubWord(s1); s2=SubWord(s2); s3=SubWord(s3);
    { uint32_t t[4]={s0,s1,s2,s3}; ShiftRows(t); s0=t[0];s1=t[1];s2=t[2];s3=t[3]; }
    s0=MixCol(s0)^g_rk[36]; s1=MixCol(s1)^g_rk[37]; s2=MixCol(s2)^g_rk[38]; s3=MixCol(s3)^g_rk[39];

#undef ROUND
    /* Round 10: SubBytes + ShiftRows + AddRoundKey (no MixColumns) */
    s0=SubWord(s0); s1=SubWord(s1); s2=SubWord(s2); s3=SubWord(s3);
    { uint32_t t[4]={s0,s1,s2,s3}; ShiftRows(t); s0=t[0];s1=t[1];s2=t[2];s3=t[3]; }
    s0^=g_rk[40]; s1^=g_rk[41]; s2^=g_rk[42]; s3^=g_rk[43];

    *(uint32_t *)(out)    = s0;
    *(uint32_t *)(out+4)  = s1;
    *(uint32_t *)(out+8)  = s2;
    *(uint32_t *)(out+12) = s3;
}

/* Benchmark wrapper */
void aes_bm_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    ensure_key(key);
    aes_bm_encrypt(in, out);
}

/* Baseline wrapper: tiny-AES-c (byte LUT, looped) for comparison */
void aes_baseline_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    static struct AES_ctx ctx;
    static uint8_t saved_key[16];
    static int rdy = 0;
    if (!rdy || memcmp(key, saved_key, 16)) {
        AES_init_ctx(&ctx, key);
        memcpy(saved_key, key, 16);
        rdy = 1;
    }
    memcpy(out, in, 16);
    AES_ECB_encrypt(&ctx, out);
}
