#ifndef MKV_WP_H
#define MKV_WP_H

/*
 * MKV-128 word-parallel, tableless implementation — RISC-V Bitmanip demo.
 *
 * Original MKV-128 source: MKV128_8bit/MKV128_8bit/MKV128.cpp
 * GF polynomial: f(x) = x^8 + x^5 + x^3 + x + 1  (reduction byte = 0x2B)
 *
 * Problems in the original implementation
 * ----------------------------------------
 * 1. Mult[256][256] = 64 KB GF-multiply lookup table.
 *    - Larger than any typical embedded L1 cache.
 *    - Every MixWords call causes dozens of cache misses → dominated by DMEM latency.
 *
 * 2. All operations are byte-oriented.
 *    - AddRoundKey:  16 XOR instructions
 *    - XWords:       48 XOR instructions (3 per byte × 16 bytes)
 *
 * What this implementation does differently
 * ------------------------------------------
 * 1. Tableless MixWords: replaces Mult[][] with on-the-fly xtime chains.
 *    Each column uses 4 word-level xtime calls (vs 13 byte-level calls in naïve form).
 *    No large table — eliminates the 64 KB DMEM footprint and all its cache misses.
 *
 * 2. Word-packed state: state stored as 4 × uint32_t (one word per column).
 *    - AddRoundKey: 4 XOR instructions instead of 16 (saves 12).
 *    - XWords:      5 XOR instructions instead of ~48 (saves ~43).
 *
 * 3. Zbb — andn (a & ~b): 1 instruction instead of (not + and) = 2.
 *    Used in xtime_w() mask operation.
 *    4 calls × 7 rounds_encrypt × 4 MixWords_cols = 112 xtime_w calls →
 *    saves 112 instructions per block.
 *
 * 4. Zbb — rori: 1 instruction instead of (srli + slli + or) = 3.
 *    Used in MixWords column rotation (k=1,2,3) and invMixWords output rotation.
 *    3 rotations × 4 cols × encrypt = saves ~144 instructions per block.
 *    Also used in XWords (5 instructions instead of ~48).
 *
 * 5. Zba — sh2add: 1 instruction for uint32_t table address scaling.
 *    Used in subcells4_zba() variant: 4 lookups × 2 SubCells per F() × (r + key_sched).
 *    Without Zba: slli 2 + add = 2 insn per lookup; with Zba: sh2add = 1 insn.
 *
 * Summary of savings per encrypt call (r=7 rounds, no key schedule):
 *   Source           | Without Bitmanip | With Zbb+Zba | Savings
 *   64 KB Mult table | ~200+ cache miss | 0 cache miss | Largest gain (×3-10×)
 *   andn in xtime_w  | 2 insn/call      | 1 insn/call  | ~112 insns/block
 *   rori in rotation | 3 insn/call      | 1 insn/call  | ~144 insns/block
 *   Word XOR (AddRK) | 16 insns         | 4 insns/call | saves 12×(r+1) insns
 *   sh2add (SubCells)| 2 insn/lookup    | 1 insn/lookup| ~16×r×2 insns (Zba only)
 */

#include <stdint.h>

/* Round counts */
#define MKV_ROUNDS_128  7
#define MKV_ROUNDS_192  8
#define MKV_ROUNDS_256  9

/* Block size in bytes */
#define MKV_BLOCK_LEN   16

/*
 * Pre-expanded key context.
 * Round keys are stored word-packed (uint32_t, little-endian bytes).
 * Total: (2*r+1) blocks × 4 words = up to (2*9+1)*4 = 76 words for r=9.
 */
#define MKV_RKEY_WORDS  ((2 * MKV_ROUNDS_256 + 1) * 4)  /* = 76 */

typedef struct {
    uint32_t rk[MKV_RKEY_WORDS]; /* round keys, word-packed */
    int      rounds;              /* 7, 8, or 9               */
} mkv_wp_ctx_t;

/*
 * Key expansion: populate *ctx from masterKey.
 * keyLen = 16 (r=7), 24 (r=8), or 32 (r=9) bytes.
 *
 * Internally runs the same V-schedule as the original, using the
 * optimised F() function (tableless MixWords, word XOR, etc.).
 */
void mkv_wp_init(mkv_wp_ctx_t *ctx, int rounds, const uint8_t *masterKey);

/*
 * Encrypt one 16-byte block.
 * Uses Zbb andn (xtime) + rori (rotation/XWords) patterns.
 * SubCells uses uint8_t S-box (byte-indexed, 1 lbu/lookup).
 */
void mkv_wp_encrypt(const mkv_wp_ctx_t *ctx,
                    const uint8_t in[16], uint8_t out[16]);

/*
 * Decrypt one 16-byte block (inverse cipher).
 */
void mkv_wp_decrypt(const mkv_wp_ctx_t *ctx,
                    const uint8_t in[16], uint8_t out[16]);

/*
 * Zba variant of encrypt: SubCells uses uint32_t S-box so GCC+Zba
 * emits sh2add for the 4× index scaling instead of slli+add.
 * Same output as mkv_wp_encrypt; only differs in SubCells lookup path.
 */
void mkv_wp_encrypt_zba(const mkv_wp_ctx_t *ctx,
                         const uint8_t in[16], uint8_t out[16]);

/*
 * Benchmark wrappers — signature matches run_benchmark():
 *   void fn(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
 *
 * Each call performs full key schedule (r=7, 128-bit key) + 1 block encrypt.
 * Note: MKV key schedule is expensive (~4× F() calls per round × 7 rounds).
 * This shows realistic cost without key reuse.
 */
void mkv_wp_bench    (const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void mkv_wp_bench_zba(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/*
 * Encrypt-only benchmark (pre-expanded key, key schedule not included).
 * Use mkv_wp_init() once, then this wrapper in the timing loop for
 * throughput-only measurement.
 */
void mkv_wp_encrypt_only(const uint8_t *rk_ctx_bytes,
                          const uint8_t in[16], uint8_t out[16]);

/*
 * Fully-optimised encrypt: always_inline hot functions (no -Os jal overhead)
 *                          + xtime_w_nomul (no mul instruction)
 *                          + subcells4_zba (sh2add)
 *                          + pack_state_zbkb (packh + pack).
 * Benchmark: key schedule + encrypt, same signature as mkv_wp_bench.
 */
void mkv_wp_encrypt_opt(const mkv_wp_ctx_t *ctx,
                         const uint8_t in[16], uint8_t out[16]);
void mkv_wp_bench_opt  (const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/*
 * Self-test against official MKV128_8bit reference test vectors.
 * Returns bitmask: bit0=enc128, bit1=dec128-rt, bit2=enc192,
 *                   bit3=enc256, bit4=zba==wp, bit5=opt==wp.
 * All-tests-pass = 0x3F.
 */
int mkv_wp_selftest(void);

#endif /* MKV_WP_H */
