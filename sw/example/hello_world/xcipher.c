/*
 * XPERM-CIPHER — Custom cipher designed for maximum RISC-V bitmanip advantage.
 *
 * Design principles:
 * 1. SubCells: 4-bit S-box via xperm4 (Zbkx) — 2 instructions vs 48 baseline
 * 2. MixColumns: word rotation via rori (Zbb) — 1 instruction vs 3 baseline
 * 3. AddRoundKey: simple XOR — same for both
 * 4. NO bit permutation (unlike PRESENT) — keeps SubCells+Mix as dominant cost
 *
 * Structure per round (simplified SPN):
 *   state ^= rk[i]         (4 XOR, same both)
 *   state = SubCells(state) (xperm4 vs nibble, THE divergence)
 *   state = MixWords(state) (rori vs srli+slli+or)
 *
 * Block: 64-bit (2×32-bit words), 16 rounds.
 *
 * Expected: SubCells = 50% of operations → xperm4 8× speedup on that 50%
 *           MixWords = 25% → rori 3× speedup on that 25%
 *           Total: ~50%×7/8 + 25%×2/3 = 44% + 17% = 35%+ savings
 */

#include <stdint.h>
#include <string.h>

/* 4-bit S-box: nonlinear permutation */
static const uint8_t XC_SBOX[16] = {
    0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD,
    0x9, 0x6, 0x1, 0xC, 0xE, 0x4, 0x7, 0x0
};

/* Pack S-box halves for xperm4 */
#define XC_SBOX_LO ( \
    ((uint32_t)XC_SBOX[0]      ) | ((uint32_t)XC_SBOX[1] <<  4) | \
    ((uint32_t)XC_SBOX[2] <<  8) | ((uint32_t)XC_SBOX[3] << 12) | \
    ((uint32_t)XC_SBOX[4] << 16) | ((uint32_t)XC_SBOX[5] << 20) | \
    ((uint32_t)XC_SBOX[6] << 24) | ((uint32_t)XC_SBOX[7] << 28)   \
)
#define XC_SBOX_HI ( \
    ((uint32_t)XC_SBOX[ 8]      ) | ((uint32_t)XC_SBOX[ 9] <<  4) | \
    ((uint32_t)XC_SBOX[10] <<  8) | ((uint32_t)XC_SBOX[11] << 12) | \
    ((uint32_t)XC_SBOX[12] << 16) | ((uint32_t)XC_SBOX[13] << 20) | \
    ((uint32_t)XC_SBOX[14] << 24) | ((uint32_t)XC_SBOX[15] << 28)   \
)

#ifdef __riscv_zbkx
static inline uint32_t do_xperm4(uint32_t sel, uint32_t table) {
    uint32_t rd;
    __asm__ volatile("xperm4 %0, %1, %2" : "=r"(rd) : "r"(sel), "r"(table));
    return rd;
}
#endif

static inline uint32_t rotl32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32u - n));
}

/* ================================================================
 * SubCells: #ifdef selects structure
 * ================================================================ */

#ifdef __riscv_zbkx
/* BITMANIP path: xperm4 parallel nibble lookup (2 xperm4 + merge = ~12 instr) */
static uint64_t xc_subcells(uint64_t state) {
    uint32_t lo = (uint32_t)state;
    uint32_t hi = (uint32_t)(state >> 32);
    uint32_t sbox_lo = XC_SBOX_LO;
    uint32_t sbox_hi = XC_SBOX_HI;

    /* Lower word */
    uint32_t lo_idx = lo & 0x77777777u;
    uint32_t lo_r0 = do_xperm4(lo_idx, sbox_lo);
    uint32_t lo_r1 = do_xperm4(lo_idx, sbox_hi);
    uint32_t lo_sel = ((lo >> 3) & 0x11111111u) * 0xFu;
    lo = (lo_r0 & ~lo_sel) | (lo_r1 & lo_sel);

    /* Upper word */
    uint32_t hi_idx = hi & 0x77777777u;
    uint32_t hi_r0 = do_xperm4(hi_idx, sbox_lo);
    uint32_t hi_r1 = do_xperm4(hi_idx, sbox_hi);
    uint32_t hi_sel = ((hi >> 3) & 0x11111111u) * 0xFu;
    hi = (hi_r0 & ~hi_sel) | (hi_r1 & hi_sel);

    return (uint64_t)lo | ((uint64_t)hi << 32);
}
#else
/* BASELINE path: nibble-by-nibble lookup (16 iterations = ~48 instr) */
static uint64_t xc_subcells(uint64_t state) {
    uint64_t result = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t nibble = (state >> (i * 4)) & 0xF;
        result |= (uint64_t)XC_SBOX[nibble] << (i * 4);
    }
    return result;
}
#endif

/* ================================================================
 * MixWords: rotate words (Zbb rori vs srli+slli+or)
 * ================================================================ */
static uint64_t xc_mixwords(uint64_t state) {
    uint32_t lo = (uint32_t)state;
    uint32_t hi = (uint32_t)(state >> 32);
    /* Mix: lo = lo ^ rotl(hi, 7), hi = hi ^ rotl(lo, 13) */
    /* Uses rori with Zbb (1 instr), srli+slli+or without (3 instr) */
    lo ^= rotl32(hi, 7);
    hi ^= rotl32(lo, 13);
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

/* ================================================================
 * Key schedule: simple XOR-based
 * ================================================================ */
typedef struct { uint64_t rk[17]; } xc_ctx_t;

void xc_init(xc_ctx_t *ctx, const uint8_t key[16]) {
    uint64_t k0, k1;
    memcpy(&k0, key, 8);
    memcpy(&k1, key + 8, 8);
    ctx->rk[0] = k0 ^ k1;
    for (int i = 1; i <= 16; i++) {
        k0 = rotl32(k0, 5) ^ k1;
        k1 = rotl32(k1, 17) ^ k0;
        ctx->rk[i] = k0 ^ k1;
    }
}

/* ================================================================
 * Encrypt: 16 rounds of AddKey + SubCells + MixWords
 * ================================================================ */
void xc_encrypt(const xc_ctx_t *ctx, const uint8_t in[8], uint8_t out[8]) {
    uint64_t state;
    memcpy(&state, in, 8);

    for (int i = 0; i < 16; i++) {
        state ^= ctx->rk[i];       /* AddRoundKey */
        state = xc_subcells(state); /* SubCells: #ifdef path */
        state = xc_mixwords(state); /* MixWords: rori path */
    }
    state ^= ctx->rk[16];  /* final AddRoundKey */

    memcpy(out, &state, 8);
}

/* Benchmark wrappers */
static xc_ctx_t g_xc_ctx;
static uint8_t g_xc_key[16];
static int g_xc_rdy = 0;

void xc_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    xc_ctx_t ctx;
    xc_init(&ctx, key);
    xc_encrypt(&ctx, in, out);
    memcpy(out + 8, out, 8);
}

void xc_bench_encrypt_only(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    if (!g_xc_rdy || memcmp(key, g_xc_key, 16)) {
        xc_init(&g_xc_ctx, key);
        memcpy(g_xc_key, key, 16);
        g_xc_rdy = 1;
    }
    xc_encrypt(&g_xc_ctx, in, out);
    memcpy(out + 8, out, 8);
}
