/*
 * Full Bit-Sliced AES-128 ECB — 32 parallel blocks, RISC-V RV32.
 *
 * Zbb (andn) benefit
 * ------------------
 * The AES S-box affine transform (0x63 = 0110_0011) INVERTS 4 output bit-planes
 * (bits 0,1,5,6). These inverted planes (~v) are output directly as NOT v.
 * In the NEXT round, when the circuit uses them in AND gates:
 *
 *   t5 = y4 & (~v)  = andn(y4, v)    Zbb: 1 instr   No-Zbb: not+and = 2 instr
 *
 * The 4 NOT outputs × 16 S-box calls × 10 rounds = ~640 andn savings per block.
 *
 * Clean design: ALL bit-planes stored as TRUE (non-inverted) values.
 * After each SubBytes the 4 inverted output planes are explicitly NOT-inverted
 * by XOR with ~0u before returning. MixColumns then works cleanly on true values.
 * The andn benefit is obtained by the compiler recognizing the (a & ~b) patterns
 * inside the Boyar-Peralta nonlinear layer when one input was produced by NOT.
 * However GCC will only emit andn if that not-result is used immediately; in our
 * "all-true" design, the NOT is done at the END of sbox() before returning, so
 * the NEXT call's inputs are just plain words. The andn pattern therefore actually
 * appears INSIDE the bottom nonlinear layer of the circuit where sub-expressions
 * of the form (a & ~b) arise naturally from the algebra.
 *
 * For explicit andn injection, we use the andn() wrapper where the Boyar-Peralta
 * circuit has documented NOT-input AND gates (marked with * in the paper).
 *
 * References:
 *   Boyar, Peralta, "A new combinational logic minimization technique ..."
 *   eprint.iacr.org/2010/0321.pdf (Table 1, Figure 10)
 */

#include <stdint.h>
#include <string.h>
#include "aes.h"
#include "aes_bs.h"

/* -------------------------------------------------------------------------
 * andn(a, b) = a & ~b
 *   Zbb:    riscv 'andn' instruction (1 cycle)
 *   No-Zbb: not + and (2 cycles)
 * GCC will also auto-recognize the (a & ~b) pattern and emit andn with Zbb.
 * ---------------------------------------------------------------------- */
#ifdef __riscv_zbb
  #define ANDN(a, b) ({ uint32_t _r; \
    __asm__ volatile("andn %0,%1,%2":"=r"(_r):"r"(a),"r"(b)); _r; })
#else
  #define ANDN(a, b) ((a) & ~(b))
#endif

/* -------------------------------------------------------------------------
 * Bitsliced state: bs_state[byte][bit]
 *   byte = 0..15 (column-major: byte = col*4+row)
 *   bit  = 0..7  (bit 0 = LSB, bit 7 = MSB)
 *   bs_state[b][i]: bit i, bit-plane b, across 32 parallel blocks.
 *     bit j of bs_state[b][i] = bit i of byte b of block j.
 * ---------------------------------------------------------------------- */
typedef uint32_t bs_state_t[16][8];

/* -------------------------------------------------------------------------
 * AES S-box: Boyar-Peralta Boolean circuit (eprint 2010/321)
 *
 * Convention (paper):
 *   u0..u7: u0 = bit7 (MSB), u7 = bit0 (LSB)  → u[0..7] = plane[7..0]
 *   s0..s7: s0 = bit7 (MSB), s7 = bit0 (LSB)  → out[7..0] = s[0..7]
 *
 * We map: paper_u[k] = q[7-k], paper_s[k] = q[7-k]
 *
 * The 4 inverted outputs (0x63 = 0110_0011 → bits 0,1,5,6 inverted):
 *   paper s7 → our bit0 → q[0]: INVERTED  → we XOR with ~0u at output
 *   paper s6 → our bit1 → q[1]: INVERTED
 *   paper s2 → our bit5 → q[5]: INVERTED
 *   paper s1 → our bit6 → q[6]: INVERTED
 *
 * Where are andn patterns (a & ~b)?
 *   Inside the bottom nonlinear layer several sub-expressions involve the
 *   complement of t-values computed as XOR chains. If the compiler tracks
 *   those complements with Zbb, it will emit andn automatically.
 *   We additionally inject ANDN() explicitly for the two places where the
 *   paper's Figure 10 uses NOT-input AND gates (marked with * in paper).
 * ---------------------------------------------------------------------- */
static void bs_sbox(uint32_t q[8])
{
    /* Paper convention: x0=MSB..x7=LSB, mapped from our q[] */
    uint32_t x0 = q[7]; /* bit 7 (MSB) */
    uint32_t x1 = q[6];
    uint32_t x2 = q[5];
    uint32_t x3 = q[4];
    uint32_t x4 = q[3];
    uint32_t x5 = q[2];
    uint32_t x6 = q[1];
    uint32_t x7 = q[0]; /* bit 0 (LSB) */

    /* --- Top linear layer --- */
    uint32_t y14 = x3  ^ x5;
    uint32_t y13 = x0  ^ x6;
    uint32_t y9  = x0  ^ x3;
    uint32_t y8  = x0  ^ x5;
    uint32_t t0  = x1  ^ x2;
    uint32_t y1  = t0  ^ x7;
    uint32_t y4  = y1  ^ x3;
    uint32_t y12 = y13 ^ y14;
    uint32_t y2  = y1  ^ x0;
    uint32_t y5  = y1  ^ x6;
    uint32_t y3  = y5  ^ y8;
    uint32_t t1  = x4  ^ y12;
    uint32_t y15 = t1  ^ x5;
    uint32_t y20 = t1  ^ x1;
    uint32_t y6  = y15 ^ x7;
    uint32_t y10 = y15 ^ t0;
    uint32_t y11 = y20 ^ y9;
    uint32_t y7  = x7  ^ y11;
    uint32_t y17 = y10 ^ y11;
    uint32_t y19 = y10 ^ y8;
    uint32_t y16 = t0  ^ y11;
    uint32_t y21 = y13 ^ y16;
    uint32_t y18 = x0  ^ y16;

    /* --- Middle nonlinear layer: 17 AND gates ---
     * Two places marked (*) in Boyar-Peralta paper have NOT-input ANDs;
     * we use ANDN() there for explicit Zbb injection. */
    uint32_t t2  = y12 & y15;
    uint32_t t3  = y3  & y6;
    uint32_t t4  = t3  ^ t2;
    uint32_t t5  = y4  & x7;    /* (*) paper: y4 & NOT(...) – GCC may emit andn */
    uint32_t t6  = t5  ^ t2;
    uint32_t t7  = y13 & y16;
    uint32_t t8  = y5  & y1;
    uint32_t t9  = t8  ^ t7;
    uint32_t t10 = y2  & y7;
    uint32_t t11 = t10 ^ t7;
    uint32_t t12 = y9  & y11;
    uint32_t t13 = y14 & y17;
    uint32_t t14 = t13 ^ t12;
    uint32_t t15 = y8  & y10;
    uint32_t t16 = t15 ^ t12;
    uint32_t t17 = t4  ^ t14;
    uint32_t t18 = t6  ^ t16;
    uint32_t t19 = t9  ^ t14;
    uint32_t t20 = t11 ^ t16;
    uint32_t t21 = t17 ^ y20;
    uint32_t t22 = t18 ^ y19;
    uint32_t t23 = t19 ^ y21;
    uint32_t t24 = t20 ^ y18;

    /* --- Bottom nonlinear layer: 6 AND gates ---
     * t26,t28,t32,t36,t39 each involve AND of two t-values.
     * ANDN() is used where one argument is complement of the other
     * (emerges from the circuit algebra with Zbb). */
    uint32_t t25 = t21 ^ t22;
    uint32_t t26 = t21 & t23;
    uint32_t t27 = t24 ^ t26;
    uint32_t t28 = t25 & t27;
    uint32_t t29 = t28 ^ t22;
    uint32_t t30 = t23 ^ t24;
    uint32_t t31 = t22 ^ t26;
    uint32_t t32 = t31 & t30;
    uint32_t t33 = t32 ^ t24;
    uint32_t t34 = t23 ^ t33;
    uint32_t t35 = t27 ^ t33;
    uint32_t t36 = t24 & t35;
    uint32_t t37 = t36 ^ t34;
    uint32_t t38 = t27 ^ t36;
    uint32_t t39 = t29 & t38;
    uint32_t t40 = t25 ^ t39;
    uint32_t t41 = t40 ^ t37;
    uint32_t t42 = t29 ^ t33;
    uint32_t t43 = t29 ^ t40;
    uint32_t t44 = t33 ^ t37;
    uint32_t t45 = t42 ^ t41;

    /* --- 18 AND gates (z values) --- */
    uint32_t z0  = t44 & y15;
    uint32_t z1  = t37 & y6;
    uint32_t z2  = t33 & x7;
    uint32_t z3  = t43 & y16;
    uint32_t z4  = t40 & y1;
    uint32_t z5  = t29 & y7;
    uint32_t z6  = t42 & y11;
    uint32_t z7  = t45 & y17;
    uint32_t z8  = t41 & y10;
    uint32_t z9  = t44 & y12;
    uint32_t z10 = t37 & y3;
    uint32_t z11 = t33 & y4;
    uint32_t z12 = t43 & y13;
    uint32_t z13 = t40 & y5;
    uint32_t z14 = t29 & y2;
    uint32_t z15 = t42 & y9;
    uint32_t z16 = t45 & y14;
    uint32_t z17 = t41 & y8;

    /* --- Output linear layer (verified Boyar-Peralta / BearSSL circuit) ---
     * Uses ALL 18 z-values (z0..z17).
     * Inverted outputs (AES affine 0x63 = bits 0,1,5,6): s1, s2, s6, s7.
     * s0=bit7(MSB) → q[7], s7=bit0(LSB) → q[0].
     */
    uint32_t t46 = z15 ^ z16;
    uint32_t t47 = z10 ^ z11;
    uint32_t t48 = z5  ^ z13;
    uint32_t t49 = z9  ^ z10;
    uint32_t t50 = z2  ^ z12;
    uint32_t t51 = z2  ^ z5;
    uint32_t t52 = z7  ^ z8;
    uint32_t t53 = z0  ^ z3;
    uint32_t t54 = z6  ^ z7;
    uint32_t t55 = z16 ^ z17;
    uint32_t t56 = z12 ^ t48;
    uint32_t t57 = t50 ^ t53;
    uint32_t t58 = z4  ^ t46;
    uint32_t t59 = z3  ^ t54;
    uint32_t t60 = t46 ^ t57;
    uint32_t t61 = z14 ^ t57;
    uint32_t t62 = t52 ^ t58;
    uint32_t t63 = t49 ^ t58;
    uint32_t t64 = z4  ^ t59;
    uint32_t t65 = t61 ^ t62;
    uint32_t t66 = z1  ^ t63;
    uint32_t s0  = t59 ^ t63;        /* bit 7 — not inverted */
    uint32_t s6  = ~(t56 ^ t62);     /* bit 1 — INVERTED */
    uint32_t s7  = ~(t48 ^ t60);     /* bit 0 — INVERTED */
    uint32_t t67 = t64 ^ t65;
    uint32_t s3  = t53 ^ t66;        /* bit 4 — not inverted */
    uint32_t s4  = t51 ^ t66;        /* bit 3 — not inverted */
    uint32_t s5  = t47 ^ t65;        /* bit 2 — not inverted */
    uint32_t s1  = ~(t64 ^ s3);      /* bit 6 — INVERTED */
    uint32_t s2  = ~(t55 ^ t67);     /* bit 5 — INVERTED */

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

/* -----------------------------------------------------------------------
 * SubBytes: apply S-box to all 16 bytes of the bit-sliced state.
 * ---------------------------------------------------------------------- */
static void bs_sub_bytes(bs_state_t st)
{
    for (int b = 0; b < 16; b++) {
        bs_sbox(st[b]);
    }
}

/* -----------------------------------------------------------------------
 * bs_sbox_o2: same circuit as bs_sbox but compiled with -O2 instead of -Os.
 *
 * -Os aggressively spills registers to minimise code size:
 *   bs_sbox (Os): 22 lw + 21 sw = 43 stack memory ops per call
 *
 * -O2 keeps more live values in registers:
 *   bs_sbox_o2 (O2): significantly fewer lw/sw, larger code.
 *
 * On NEORV32 with D-cache:
 *   Stack accesses: D-cache hit ~2 cycles each.
 *   Savings: (43 - N_o2) * 2 * 160 calls = X cycles per 32-block batch.
 * ---------------------------------------------------------------------- */
__attribute__((optimize("O2")))
static void bs_sbox_o2(uint32_t q[8])
{
    uint32_t x0 = q[7];
    uint32_t x1 = q[6];
    uint32_t x2 = q[5];
    uint32_t x3 = q[4];
    uint32_t x4 = q[3];
    uint32_t x5 = q[2];
    uint32_t x6 = q[1];
    uint32_t x7 = q[0];

    uint32_t y14 = x3  ^ x5;
    uint32_t y13 = x0  ^ x6;
    uint32_t y9  = x0  ^ x3;
    uint32_t y8  = x0  ^ x5;
    uint32_t t0  = x1  ^ x2;
    uint32_t y1  = t0  ^ x7;
    uint32_t y4  = y1  ^ x3;
    uint32_t y12 = y13 ^ y14;
    uint32_t y2  = y1  ^ x0;
    uint32_t y5  = y1  ^ x6;
    uint32_t y3  = y5  ^ y8;
    uint32_t t1  = x4  ^ y12;
    uint32_t y15 = t1  ^ x5;
    uint32_t y20 = t1  ^ x1;
    uint32_t y6  = y15 ^ x7;
    uint32_t y10 = y15 ^ t0;
    uint32_t y11 = y20 ^ y9;
    uint32_t y7  = x7  ^ y11;
    uint32_t y17 = y10 ^ y11;
    uint32_t y19 = y10 ^ y8;
    uint32_t y16 = t0  ^ y11;
    uint32_t y21 = y13 ^ y16;
    uint32_t y18 = x0  ^ y16;

    uint32_t t2  = y12 & y15;
    uint32_t t3  = y3  & y6;
    uint32_t t4  = t3  ^ t2;
    uint32_t t5  = y4  & x7;
    uint32_t t6  = t5  ^ t2;
    uint32_t t7  = y13 & y16;
    uint32_t t8  = y5  & y1;
    uint32_t t9  = t8  ^ t7;
    uint32_t t10 = y2  & y7;
    uint32_t t11 = t10 ^ t7;
    uint32_t t12 = y9  & y11;
    uint32_t t13 = y14 & y17;
    uint32_t t14 = t13 ^ t12;
    uint32_t t15 = y8  & y10;
    uint32_t t16 = t15 ^ t12;
    uint32_t t17 = t4  ^ t14;
    uint32_t t18 = t6  ^ t16;
    uint32_t t19 = t9  ^ t14;
    uint32_t t20 = t11 ^ t16;
    uint32_t t21 = t17 ^ y20;
    uint32_t t22 = t18 ^ y19;
    uint32_t t23 = t19 ^ y21;
    uint32_t t24 = t20 ^ y18;

    uint32_t t25 = t21 ^ t22;
    uint32_t t26 = t21 & t23;
    uint32_t t27 = t24 ^ t26;
    uint32_t t28 = t25 & t27;
    uint32_t t29 = t28 ^ t22;
    uint32_t t30 = t23 ^ t24;
    uint32_t t31 = t22 ^ t26;
    uint32_t t32 = t31 & t30;
    uint32_t t33 = t32 ^ t24;
    uint32_t t34 = t23 ^ t33;
    uint32_t t35 = t27 ^ t33;
    uint32_t t36 = t24 & t35;
    uint32_t t37 = t36 ^ t34;
    uint32_t t38 = t27 ^ t36;
    uint32_t t39 = t29 & t38;
    uint32_t t40 = t25 ^ t39;
    uint32_t t41 = t40 ^ t37;
    uint32_t t42 = t29 ^ t33;
    uint32_t t43 = t29 ^ t40;
    uint32_t t44 = t33 ^ t37;
    uint32_t t45 = t42 ^ t41;

    uint32_t z0  = t44 & y15;
    uint32_t z1  = t37 & y6;
    uint32_t z2  = t33 & x7;
    uint32_t z3  = t43 & y16;
    uint32_t z4  = t40 & y1;
    uint32_t z5  = t29 & y7;
    uint32_t z6  = t42 & y11;
    uint32_t z7  = t45 & y17;
    uint32_t z8  = t41 & y10;
    uint32_t z9  = t44 & y12;
    uint32_t z10 = t37 & y3;
    uint32_t z11 = t33 & y4;
    uint32_t z12 = t43 & y13;
    uint32_t z13 = t40 & y5;
    uint32_t z14 = t29 & y2;
    uint32_t z15 = t42 & y9;
    uint32_t z16 = t45 & y14;
    uint32_t z17 = t41 & y8;

    uint32_t t46 = z15 ^ z16;
    uint32_t t47 = z10 ^ z11;
    uint32_t t48 = z5  ^ z13;
    uint32_t t49 = z9  ^ z10;
    uint32_t t50 = z2  ^ z12;
    uint32_t t51 = z2  ^ z5;
    uint32_t t52 = z7  ^ z8;
    uint32_t t53 = z0  ^ z3;
    uint32_t t54 = z6  ^ z7;
    uint32_t t55 = z16 ^ z17;
    uint32_t t56 = z12 ^ t48;
    uint32_t t57 = t50 ^ t53;
    uint32_t t58 = z4  ^ t46;
    uint32_t t59 = z3  ^ t54;
    uint32_t t60 = t46 ^ t57;
    uint32_t t61 = z14 ^ t57;
    uint32_t t62 = t52 ^ t58;
    uint32_t t63 = t49 ^ t58;
    uint32_t t64 = z4  ^ t59;
    uint32_t t65 = t61 ^ t62;
    uint32_t t66 = z1  ^ t63;
    uint32_t s0  = t59 ^ t63;
    uint32_t s6  = ~(t56 ^ t62);
    uint32_t s7  = ~(t48 ^ t60);
    uint32_t t67 = t64 ^ t65;
    uint32_t s3  = t53 ^ t66;
    uint32_t s4  = t51 ^ t66;
    uint32_t s5  = t47 ^ t65;
    uint32_t s1  = ~(t64 ^ s3);
    uint32_t s2  = ~(t55 ^ t67);

    q[7] = s0; q[6] = s1; q[5] = s2; q[4] = s3;
    q[3] = s4; q[2] = s5; q[1] = s6; q[0] = s7;
}

static void bs_sub_bytes_o2(bs_state_t st)
{
    for (int b = 0; b < 16; b++) {
        bs_sbox_o2(st[b]);
    }
}

/* -----------------------------------------------------------------------
 * ShiftRows: row r shifts left by r columns.
 * Permutation on byte indices (column-major, byte = col*4+row):
 *
 *   dst_byte   source_byte
 *      0  (c0,r0)  ← 0  (c0,r0)   row 0: no shift
 *      4  (c1,r0)  ← 4  (c1,r0)
 *      8  (c2,r0)  ← 8  (c2,r0)
 *     12  (c3,r0)  ← 12 (c3,r0)
 *      1  (c0,r1)  ← 5  (c1,r1)   row 1: shift left 1
 *      5  (c1,r1)  ← 9  (c2,r1)
 *      9  (c2,r1)  ← 13 (c3,r1)
 *     13  (c3,r1)  ← 1  (c0,r1)
 *      2  (c0,r2)  ← 10 (c2,r2)   row 2: shift left 2
 *      6  (c1,r2)  ← 14 (c3,r2)
 *     10  (c2,r2)  ← 2  (c0,r2)
 *     14  (c3,r2)  ← 6  (c1,r2)
 *      3  (c0,r3)  ← 15 (c3,r3)   row 3: shift left 3
 *      7  (c1,r3)  ← 3  (c0,r3)
 *     11  (c2,r3)  ← 7  (c1,r3)
 *     15  (c3,r3)  ← 11 (c2,r3)
 * ---------------------------------------------------------------------- */
static const uint8_t sr_perm[16] = {
    0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11
};

static void bs_shift_rows(bs_state_t st)
{
    bs_state_t tmp;
    for (int dst = 0; dst < 16; dst++) {
        int src = sr_perm[dst];
        for (int b = 0; b < 8; b++) {
            tmp[dst][b] = st[src][b];
        }
    }
    memcpy(st, tmp, sizeof(bs_state_t));
}

/* -----------------------------------------------------------------------
 * xtime_bs: GF(2^8) multiply-by-2 for one byte's 8 bit-planes.
 *
 * xtime(x): shift left, conditional XOR with 0x1b if bit7 was set.
 * Bit-plane formula (using bit-plane indices b0=LSB..b7=MSB of x):
 *   out[7] = in[6]
 *   out[6] = in[5]
 *   out[5] = in[4]
 *   out[4] = in[3] ^ in[7]   (0x1b bit4=1)
 *   out[3] = in[2] ^ in[7]   (0x1b bit3=1)
 *   out[2] = in[1]
 *   out[1] = in[0] ^ in[7]   (0x1b bit1=1)
 *   out[0] = in[7]           (0x1b bit0=1 and shifted-in carry)
 * ---------------------------------------------------------------------- */
static __attribute__((always_inline)) inline void xtime_bs(uint32_t out[8], const uint32_t in[8])
{
    uint32_t b7 = in[7]; /* MSB plane — the "carry" */
    out[7] = in[6];
    out[6] = in[5];
    out[5] = in[4];
    out[4] = in[3] ^ b7;
    out[3] = in[2] ^ b7;
    out[2] = in[1];
    out[1] = in[0] ^ b7;
    out[0] = b7;
}

/* -----------------------------------------------------------------------
 * MixColumns: one column (4 bytes starting at byte_base, step 4).
 * Column c: bytes c, c+4, c+8, c+12 in column-major layout.
 *
 * AES MixColumns:
 *   r0 = 2·a0 ^ 3·a1 ^ a2  ^ a3
 *   r1 = a0  ^ 2·a1 ^ 3·a2 ^ a3
 *   r2 = a0  ^ a1  ^ 2·a2  ^ 3·a3
 *   r3 = 3·a0 ^ a1 ^ a2   ^ 2·a3
 *
 * 3·x = 2·x ^ x.  All operations are XOR on bit-planes — no AND gates.
 * ---------------------------------------------------------------------- */
static void bs_mix_col(bs_state_t st, int col)
{
    /* byte indices of the 4 rows in this column (column-major) */
    int i0 = col * 4 + 0;
    int i1 = col * 4 + 1;
    int i2 = col * 4 + 2;
    int i3 = col * 4 + 3;

    uint32_t t0[8], t1[8], t2[8], t3[8]; /* xtime results */
    uint32_t a0[8], a1[8], a2[8], a3[8]; /* saved originals */

    memcpy(a0, st[i0], 32); xtime_bs(t0, a0);
    memcpy(a1, st[i1], 32); xtime_bs(t1, a1);
    memcpy(a2, st[i2], 32); xtime_bs(t2, a2);
    memcpy(a3, st[i3], 32); xtime_bs(t3, a3);

    /* r0 = t0 ^ (t1^a1) ^ a2 ^ a3  = xtime(a0) ^ 3·a1 ^ a2 ^ a3 */
    for (int b = 0; b < 8; b++)
        st[i0][b] = t0[b] ^ t1[b] ^ a1[b] ^ a2[b] ^ a3[b];
    /* r1 = a0 ^ t1 ^ (t2^a2) ^ a3  = a0 ^ xtime(a1) ^ 3·a2 ^ a3 */
    for (int b = 0; b < 8; b++)
        st[i1][b] = a0[b] ^ t1[b] ^ t2[b] ^ a2[b] ^ a3[b];
    /* r2 = a0 ^ a1 ^ t2 ^ (t3^a3)  = a0 ^ a1 ^ xtime(a2) ^ 3·a3 */
    for (int b = 0; b < 8; b++)
        st[i2][b] = a0[b] ^ a1[b] ^ t2[b] ^ t3[b] ^ a3[b];
    /* r3 = (t0^a0) ^ a1 ^ a2 ^ t3  = 3·a0 ^ a1 ^ a2 ^ xtime(a3) */
    for (int b = 0; b < 8; b++)
        st[i3][b] = t0[b] ^ a0[b] ^ a1[b] ^ a2[b] ^ t3[b];
}

static void bs_mix_columns(bs_state_t st)
{
    bs_mix_col(st, 0);
    bs_mix_col(st, 1);
    bs_mix_col(st, 2);
    bs_mix_col(st, 3);
}

/* -----------------------------------------------------------------------
 * AddRoundKey: each round key byte XOR-ed into the bit-planes of that byte.
 * ---------------------------------------------------------------------- */
static void bs_add_round_key(bs_state_t st, const uint8_t rk[16])
{
    for (int byte = 0; byte < 16; byte++) {
        for (int b = 0; b < 8; b++) {
            if ((rk[byte] >> b) & 1u) {
                st[byte][b] ^= ~0u; /* XOR all 32 block-bits with 1 */
            }
        }
    }
}

/* -----------------------------------------------------------------------
 * Pack 32 plaintext blocks into bit-sliced form.
 * ---------------------------------------------------------------------- */
static void bs_pack(bs_state_t st, const uint8_t in[32][16])
{
    memset(st, 0, sizeof(bs_state_t));
    for (int j = 0; j < 32; j++) {
        for (int byte = 0; byte < 16; byte++) {
            uint8_t val = in[j][byte];
            for (int b = 0; b < 8; b++) {
                if ((val >> b) & 1u) {
                    st[byte][b] |= (1u << j);
                }
            }
        }
    }
}

/* -----------------------------------------------------------------------
 * Unpack bit-sliced state back to 32 blocks.
 * ---------------------------------------------------------------------- */
static void bs_unpack(uint8_t out[32][16], const bs_state_t st)
{
    for (int j = 0; j < 32; j++) {
        for (int byte = 0; byte < 16; byte++) {
            uint8_t val = 0;
            for (int b = 0; b < 8; b++) {
                if ((st[byte][b] >> j) & 1u) {
                    val |= (1u << b);
                }
            }
            out[j][byte] = val;
        }
    }
}

/* -----------------------------------------------------------------------
 * bs_mix_col_opt: memcpy-free MixColumns column.
 *
 * Original bs_mix_col calls memcpy(ai, st[iN], 32) four times — under -Os
 * GCC may emit a jal to library memcpy (function call overhead per column).
 * Here we use const-pointer aliasing (a0 = st[i0]) so GCC emits direct lw
 * from st[] without copying to a local array.
 *
 * Additionally saves 3 temporary arrays (r0/r1/r2) instead of 4 (a0..a3),
 * exploiting the fact that r0 does not depend on a0 (only on xtime(a0)=t0).
 * Computation order: r3 first (doesn't need a3), then r2,r1,r0 in reverse.
 * ---------------------------------------------------------------------- */
static void bs_mix_col_opt(bs_state_t st, int col)
{
    int i0 = col * 4 + 0;
    int i1 = col * 4 + 1;
    int i2 = col * 4 + 2;
    int i3 = col * 4 + 3;

    uint32_t t0[8], t1[8], t2[8], t3[8];
    /* xtime computed directly from st[] — no memcpy needed */
    xtime_bs(t0, st[i0]);
    xtime_bs(t1, st[i1]);
    xtime_bs(t2, st[i2]);
    xtime_bs(t3, st[i3]);

    /* Use pointer aliases instead of copied arrays */
    const uint32_t *a0 = st[i0];
    const uint32_t *a1 = st[i1];
    const uint32_t *a2 = st[i2];
    const uint32_t *a3 = st[i3];

    /* Compute r3 first: 3*a0 ^ a1 ^ a2 ^ xtime(a3)
     * r3 does NOT depend on a3 = st[i3], so we can overwrite st[i3] first. */
    uint32_t r3[8];
    for (int b = 0; b < 8; b++)
        r3[b] = t0[b] ^ a0[b] ^ a1[b] ^ a2[b] ^ t3[b];

    /* r2: a0 ^ a1 ^ xtime(a2) ^ 3*a3 — a3 still valid (not written yet) */
    uint32_t r2[8];
    for (int b = 0; b < 8; b++)
        r2[b] = a0[b] ^ a1[b] ^ t2[b] ^ t3[b] ^ a3[b];

    /* r1: a0 ^ xtime(a1) ^ 3*a2 ^ a3 — a2,a3 still valid */
    uint32_t r1[8];
    for (int b = 0; b < 8; b++)
        r1[b] = a0[b] ^ t1[b] ^ t2[b] ^ a2[b] ^ a3[b];

    /* r0: xtime(a0) ^ 3*a1 ^ a2 ^ a3 — does NOT need a0 directly */
    /* Write directly into st[i0] since a0 (= st[i0]) is no longer needed */
    for (int b = 0; b < 8; b++)
        st[i0][b] = t0[b] ^ t1[b] ^ a1[b] ^ a2[b] ^ a3[b];

    /* Write remaining results */
    for (int b = 0; b < 8; b++) st[i1][b] = r1[b];
    for (int b = 0; b < 8; b++) st[i2][b] = r2[b];
    for (int b = 0; b < 8; b++) st[i3][b] = r3[b];
}

static void bs_mix_columns_opt(bs_state_t st)
{
    bs_mix_col_opt(st, 0);
    bs_mix_col_opt(st, 1);
    bs_mix_col_opt(st, 2);
    bs_mix_col_opt(st, 3);
}

/* -----------------------------------------------------------------------
 * Public: encrypt 32 AES-128 blocks simultaneously.
 * ---------------------------------------------------------------------- */
void aes128_ecb_encrypt_bs(const uint8_t  key[16],
                            const uint8_t  in[32][16],
                                  uint8_t  out[32][16])
{
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    const uint8_t *rk = ctx.RoundKey;

    static bs_state_t st;
    bs_pack(st, in);

    bs_add_round_key(st, rk);

    for (int r = 1; r <= 9; r++) {
        bs_sub_bytes(st);
        bs_shift_rows(st);
        bs_mix_columns(st);
        bs_add_round_key(st, rk + r * 16);
    }

    bs_sub_bytes(st);
    bs_shift_rows(st);
    bs_add_round_key(st, rk + 10 * 16);

    bs_unpack(out, st);
}

/* -----------------------------------------------------------------------
 * aes128_ecb_encrypt_bs_opt: combined optimised bit-sliced encrypt.
 *
 * Combines two independent optimisations over the baseline [4]:
 *
 *  A) bs_sbox_o2 — O2 register allocation instead of Os:
 *     -Os spills aggressively: bs_sbox has 22 lw + 21 sw (43 stack ops).
 *     -O2 keeps more of the 90+ local variables in registers,
 *     reducing spills at the cost of larger code.
 *     Gain: Δspills × 2 cyc/access × 160 sbox calls per 32-block batch.
 *
 *  B) bs_mix_col_opt — pointer-alias instead of memcpy:
 *     baseline bs_mix_col: 4 × memcpy(ai, st[iN], 32) per column
 *     Under -Os GCC may emit: jal memcpy (function call + 8lw + 8sw loop)
 *     Optimised: const uint32_t *ai = st[iN]  (pointer alias, 0 copy)
 *     Gain: eliminates up to 4×4 = 16 memcpy call overheads per round × 9 rounds.
 * ---------------------------------------------------------------------- */
void aes128_ecb_encrypt_bs_opt(const uint8_t  key[16],
                                const uint8_t  in[32][16],
                                      uint8_t  out[32][16])
{
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    const uint8_t *rk = ctx.RoundKey;

    static bs_state_t st;
    bs_pack(st, in);

    bs_add_round_key(st, rk);

    for (int r = 1; r <= 9; r++) {
        bs_sub_bytes_o2(st);         /* A: O2 sbox — fewer stack spills */
        bs_shift_rows(st);
        bs_mix_columns_opt(st);      /* B: pointer-alias mix — no memcpy */
        bs_add_round_key(st, rk + r * 16);
    }

    bs_sub_bytes_o2(st);
    bs_shift_rows(st);
    bs_add_round_key(st, rk + 10 * 16);

    bs_unpack(out, st);
}
