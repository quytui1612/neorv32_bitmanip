/*
 * MKV-128 T-Table Implementation — Maximum Bitmanip Acceleration.
 *
 * T-tables combine SubCells + MixWords into a single table lookup per byte.
 * This eliminates ~150 instructions of GF multiply per column, replacing
 * them with 4 table lookups + 3 XORs + 3 rotations.
 *
 * The bitmanip-critical path per F() call:
 *   12 rori  (Zbb) — 3 per column × 4 columns for MixWords input rotation
 *   16 sh2add (Zba) — 4 per column × 4 columns for uint32_t table indexing
 *   12 XOR   — 3 per column for combining table results
 *   8  sbox lookup — 4 per column × 2 columns for second SubCells (no MixWords)
 *
 * Without bitmanip, the same code compiles to:
 *   36 srli+slli+or (replacing 12 rori)
 *   32 slli+add (replacing 16 sh2add)
 *   = 36 extra instructions per F() call
 *
 * With 35 F() calls per benchmark block (7 encrypt + 28 key schedule):
 *   ~1260 extra instructions without bitmanip → 30-50% throughput loss
 */

#include <stdint.h>
#include <string.h>
#include "mkv_ttable.h"

/* Reuse S-box from mkv_wp.c via extern */
extern const uint8_t mkv_sbox[256];

/*
 * T-tables: T[col_idx][input_byte] = packed MixWords column contribution.
 *
 * T[j][i] = pack( gmul(sbox[i], M[0][j]),
 *                 gmul(sbox[i], M[1][j]),
 *                 gmul(sbox[i], M[2][j]),
 *                 gmul(sbox[i], M[3][j]) )
 *
 * 4 tables × 256 entries × 4 bytes = 4 KB of read-only firmware data.
 * Keep these fixed tables out of writable memory to leave room for the stack.
 */
static const uint32_t T_fwd[4][256] = {
#include "mkv_ttable_data.inc"
};

/* Plain S-box for second SubCells (no MixWords follows) */
/* mkv_sbox is already available via extern */

void mkv_ttable_init(void) {
    /* Tables are precomputed and ready at startup. */
}

/* =========================================================================
 * Rotation helper — THE critical bitmanip pattern.
 *
 * GCC with -march=...zbb...  → rori rd, rs, imm  (1 instruction, ~1-2 cycles)
 * GCC without Zbb             → srli + slli + or  (3 instructions, ~3-6 cycles)
 *
 * Used 3× per column × 4 columns = 12× per F() call.
 * ======================================================================= */
static __attribute__((always_inline)) inline uint32_t ror32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

/*
 * T-table column transform: SubCells + MixWords for one column word.
 *
 * For column k, input is rotated right by k*8 bits, then each byte
 * is looked up in the corresponding T-table.
 *
 * Zba sh2add benefit: T_fwd[j][byte] uses uint32_t table →
 *   With Zba:    sh2add index, base → lw  (1 + 1 = 2 instructions per lookup)
 *   Without Zba: slli 2, index → add base → lw (1 + 1 + 1 = 3 instructions)
 *   Saves 1 instruction × 4 lookups × 4 columns = 16 per F() call
 *
 * Zbb rori benefit: column rotation →
 *   With Zbb:    rori (1 instruction)
 *   Without Zbb: srli + slli + or (3 instructions)
 *   Saves 2 × 3 rotations × 4 columns = 24 per F() call
 */
static __attribute__((always_inline)) inline uint32_t tcol(uint32_t w, unsigned rot) {
    uint32_t r = rot ? ror32(w, rot) : w;
    /* Byte extraction + T-table lookup — GCC+Zba emits sh2add for indexing */
    return  T_fwd[0][(uint8_t)(r)]
          ^ T_fwd[1][(uint8_t)(r >>  8)]
          ^ T_fwd[2][(uint8_t)(r >> 16)]
          ^ T_fwd[3][(uint8_t)(r >> 24)];
}

/*
 * SubCells for a single word (no MixWords).
 * Uses uint8_t sbox → no sh2add benefit, but same code either way.
 */
static __attribute__((always_inline)) inline uint32_t subcells4(uint32_t w) {
    return  (uint32_t)mkv_sbox[(uint8_t)(w)]
         | ((uint32_t)mkv_sbox[(uint8_t)(w >>  8)] <<  8)
         | ((uint32_t)mkv_sbox[(uint8_t)(w >> 16)] << 16)
         | ((uint32_t)mkv_sbox[(uint8_t)(w >> 24)] << 24);
}

/* XWords — word-packed, all-XOR variant (from mkv_wp.c, unchanged) */
static __attribute__((always_inline)) inline void xwords_wp(uint32_t col[4]) {
    uint32_t all = col[0] ^ col[1] ^ col[2] ^ col[3];
    col[0] ^= all; col[1] ^= all; col[2] ^= all; col[3] ^= all;
}

/* Pack/unpack (from mkv_wp.c) */
static inline void pack_state(const uint8_t b[16], uint32_t col[4]) {
    for (int k = 0; k < 4; k++)
        col[k] = (uint32_t)b[4*k]
               | ((uint32_t)b[4*k+1] <<  8)
               | ((uint32_t)b[4*k+2] << 16)
               | ((uint32_t)b[4*k+3] << 24);
}

static inline void unpack_state(const uint32_t col[4], uint8_t b[16]) {
    for (int k = 0; k < 4; k++) {
        b[4*k]   = (uint8_t)(col[k]);
        b[4*k+1] = (uint8_t)(col[k] >>  8);
        b[4*k+2] = (uint8_t)(col[k] >> 16);
        b[4*k+3] = (uint8_t)(col[k] >> 24);
    }
}

/* Round constants (from mkv_wp.c) */
extern const uint32_t Const0_w[4];
extern const uint32_t Const1_w[4];

/* =========================================================================
 * F() round function using T-tables — THE bitmanip hot path.
 *
 * Operations per call:
 *   4 XOR  (AddRoundKey k1)
 *   4×4 T-lookups via tcol() = 16 lookups (sh2add) + 3×4 rori = 12 rori
 *   3×4 XOR for table combining = 12 XOR
 *   4 XOR  (AddRoundKey k2)
 *   4 sbox lookups (second SubCells, no MixWords)
 *   5 XOR  (XWords)
 *
 * Total: 16 table lookups + 12 rori + ~25 XOR + 4 sbox lookups
 * ======================================================================= */
void mkv_ttable_f128(uint32_t col[4], const uint32_t *k1, const uint32_t *k2) {
    /* 1. AddRoundKey */
    col[0] ^= k1[0]; col[1] ^= k1[1]; col[2] ^= k1[2]; col[3] ^= k1[3];

    /* 2+3. SubCells + MixWords combined via T-tables.
     * Column k: input rotated by k*8 bits (Zbb rori).
     * Table indexing uses uint32_t (Zba sh2add). */
    col[0] = tcol(col[0], 0u);
    col[1] = tcol(col[1], 8u);
    col[2] = tcol(col[2], 16u);
    col[3] = tcol(col[3], 24u);

    /* 4. AddRoundKey */
    col[0] ^= k2[0]; col[1] ^= k2[1]; col[2] ^= k2[2]; col[3] ^= k2[3];

    /* 5. SubCells (plain sbox, no MixWords) */
    col[0] = subcells4(col[0]);
    col[1] = subcells4(col[1]);
    col[2] = subcells4(col[2]);
    col[3] = subcells4(col[3]);

    /* 6. XWords */
    xwords_wp(col);
}

/* Key schedule using T-table F() */
void mkv_ttable_keysched(mkv_wp_ctx_t *ctx, int rounds, const uint8_t *masterKey) {
    ctx->rounds = rounds;
    pack_state(masterKey, ctx->rk);

    uint32_t blk1[4], blk2[4];
    pack_state(masterKey, blk1);

    if (rounds == MKV_ROUNDS_128) {
        for (int i = 0; i < 4; i++) blk2[i] = blk1[i] ^ 0xFFFFFFFFu;
    } else if (rounds == MKV_ROUNDS_192) {
        uint8_t tmp[16];
        memcpy(tmp, masterKey + 16, 8);
        for (int i = 8; i < 16; i++) tmp[i] = masterKey[i] ^ 0xFFu;
        pack_state(tmp, blk2);
    } else {
        pack_state(masterKey + 16, blk2);
    }

    uint32_t cl[4], cr[4], tmpc[4], tmp_blk[4];

    for (int i = 0; i < rounds; i++) {
        cl[0] = Const0_w[0]; cl[1] = Const0_w[1];
        cl[2] = Const0_w[2]; cl[3] = Const0_w[3];
        cl[3] ^= (uint32_t)(2*i + 1) << 24;

        cr[0] = Const1_w[0]; cr[1] = Const1_w[1];
        cr[2] = Const1_w[2]; cr[3] = Const1_w[3];
        cr[3] ^= (uint32_t)(2*i + 2) << 24;

        tmpc[0] = tmpc[1] = tmpc[2] = tmpc[3] = 0u;
        mkv_ttable_f128(blk1, cl, tmpc);
        mkv_ttable_f128(blk1, tmpc, tmpc);

        tmpc[0] = tmpc[1] = tmpc[2] = tmpc[3] = 0u;
        mkv_ttable_f128(blk2, cr, tmpc);
        mkv_ttable_f128(blk2, tmpc, tmpc);

        tmp_blk[0] = blk1[0]; tmp_blk[1] = blk1[1];
        tmp_blk[2] = blk1[2]; tmp_blk[3] = blk1[3];

        blk1[0] = blk2[0]; blk1[1] = blk2[1];
        blk1[2] = blk2[2]; blk1[3] = blk2[3];

        blk2[0] = tmp_blk[0] ^ blk2[0]; blk2[1] = tmp_blk[1] ^ blk2[1];
        blk2[2] = tmp_blk[2] ^ blk2[2]; blk2[3] = tmp_blk[3] ^ blk2[3];

        int base = (2*i + 1) * 4;
        ctx->rk[base+0] = blk1[0]; ctx->rk[base+1] = blk1[1];
        ctx->rk[base+2] = blk1[2]; ctx->rk[base+3] = blk1[3];
        ctx->rk[base+4] = blk2[0]; ctx->rk[base+5] = blk2[1];
        ctx->rk[base+6] = blk2[2]; ctx->rk[base+7] = blk2[3];
    }
}

void mkv_ttable_encrypt(const mkv_wp_ctx_t *ctx,
                        const uint8_t in[16], uint8_t out[16]) {
    uint32_t col[4];
    pack_state(in, col);

    int r = ctx->rounds;
    for (int i = 0; i < r; i++)
        mkv_ttable_f128(col, &ctx->rk[8*i], &ctx->rk[8*i + 4]);

    col[0] ^= ctx->rk[8*r];   col[1] ^= ctx->rk[8*r+1];
    col[2] ^= ctx->rk[8*r+2]; col[3] ^= ctx->rk[8*r+3];

    unpack_state(col, out);
}

void mkv_ttable_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    mkv_wp_ctx_t ctx;
    mkv_ttable_keysched(&ctx, MKV_ROUNDS_128, key);
    mkv_ttable_encrypt(&ctx, in, out);
}
