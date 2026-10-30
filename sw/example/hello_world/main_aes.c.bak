// ================================================================================ //
// The NEORV32 RISC-V Processor - https://github.com/stnolting/neorv32              //
// Copyright (c) NEORV32 contributors.                                              //
// Copyright (c) 2020 - 2025 Stephan Nolting. All rights reserved.                  //
// Licensed under the BSD-3-Clause license, see LICENSE for details.                //
// SPDX-License-Identifier: BSD-3-Clause                                            //
// ================================================================================ //


/**********************************************************************//**
 * @file hello_world/main.c
 * @brief AES-128 ECB demo using tiny-AES-c on NEORV32.
 **************************************************************************/

#include <neorv32.h>
#include <stdint.h>
#include "aes.h"      // from tiny-AES-c
#include "aes_zkne.h" // Zkne scalar-crypto accelerated AES
#include "aes_wp.h"   // word-parallel AES (Zbb: ror + andn benefit)
#include "aes_bs.h"   // full bit-sliced AES (Boyar-Peralta S-box, 32 parallel blocks)
#include "speck.h"    // SPECK-64/128 ARX cipher (Zbb rori demo, no S-box)
#include "magma.h"   // Magma (GOST R 34.12-2015): pre-rotated vs rori comparison
#include "mkv_wp.h"  // MKV-128 word-parallel tableless (Zbb andn+rori, Zba sh2add)

/**********************************************************************//**
 * @name User configuration
 **************************************************************************/
/**@{*/
/** UART BAUD rate */
#define BAUD_RATE 19200
/**@}*/


// Print one byte as two hex digits
static void print_byte_hex(uint8_t b) {
  const char hex[] = "0123456789abcdef";
  char s[3];
  s[0] = hex[(b >> 4) & 0x0F];
  s[1] = hex[b & 0x0F];
  s[2] = '\0';
  neorv32_uart0_puts(s);
}

// Print buffer as hex string
static void print_hex(const char *label, const uint8_t *buf, size_t len) {
  neorv32_uart0_puts(label);
  for (size_t i = 0; i < len; i++) {
    print_byte_hex(buf[i]);
  }
  neorv32_uart0_puts("\n");
}

// Encrypt one 16-byte block using AES-128 ECB
void aes128_ecb_encrypt_block(const uint8_t key[16],
                              const uint8_t in[16],
                              uint8_t out[16]) {
  struct AES_ctx ctx;
  uint8_t tmp[16];

  for (int i = 0; i < 16; i++) {
    tmp[i] = in[i];
  }

  AES_init_ctx(&ctx, key);
  AES_ECB_encrypt(&ctx, tmp);

  for (int i = 0; i < 16; i++) {
    out[i] = tmp[i];
  }
}

// Decrypt one 16-byte block using AES-128 ECB
void aes128_ecb_decrypt_block(const uint8_t key[16],
                              const uint8_t in[16],
                              uint8_t out[16]) {
  struct AES_ctx ctx;
  uint8_t tmp[16];

  for (int i = 0; i < 16; i++) {
    tmp[i] = in[i];
  }

  AES_init_ctx(&ctx, key);
  AES_ECB_decrypt(&ctx, tmp);

  for (int i = 0; i < 16; i++) {
    out[i] = tmp[i];
  }
}


// Generic benchmark helper: returns cycles per block
static uint32_t run_benchmark(const char *label,
                             void (*enc)(const uint8_t*, const uint8_t*, uint8_t*),
                             const uint8_t key[16],
                             const uint8_t plaintext[16]) {
  const uint32_t N_BLOCKS = 1000;
  uint8_t out[16];

  uint64_t t0 = neorv32_cpu_get_cycle();
  for (uint32_t i = 0; i < N_BLOCKS; i++) {
    enc(key, plaintext, out);
  }
  uint64_t t1 = neorv32_cpu_get_cycle();

  uint32_t cycles      = (uint32_t)(t1 - t0);
  uint32_t cyc_per_blk = cycles / N_BLOCKS;

  uint32_t f_clk = NEORV32_SYSINFO->CLK;
  uint64_t bits_total    = (uint64_t)N_BLOCKS * 128u;
  uint64_t throughput_bps = (bits_total * (uint64_t)f_clk) / (uint64_t)cycles;
  uint32_t throughput_kbps = (uint32_t)(throughput_bps / 1000u);

  neorv32_uart0_puts(label);
  neorv32_uart0_printf("Cycles/blk : %u\n", cyc_per_blk);
  neorv32_uart0_printf("Throughput : %u kbit/s\n", throughput_kbps);

  return cyc_per_blk;
}

// Benchmark AES-128 ECB: measure cycles/block and throughput
static void aes_benchmark(void) {
  const uint8_t key[16] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
  };
  const uint8_t plaintext[16] = {
    0x6b, 0xc1, 0xbe, 0xe2,
    0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11,
    0x73, 0x93, 0x17, 0x2a
  };

  neorv32_uart0_puts("\n--- Benchmark (1000 blocks each) ---\n");

  uint32_t cyc_soft = run_benchmark("[1] Soft AES (LUT, byte) ", aes128_ecb_encrypt_block, key, plaintext);
  uint32_t cyc_wp   = run_benchmark("[2] Word-par (Zbb: ror)  ", aes128_ecb_encrypt_wp,    key, plaintext);

  // Speedup of word-parallel vs soft
  {
    uint32_t s = (cyc_soft * 10u) / cyc_wp;
    neorv32_uart0_printf("  [2] vs [1] speedup : %u.", s / 10);
    neorv32_uart0_printf("%ux\n", s % 10);
  }

#ifdef __riscv_zkne
  uint32_t cyc_zkne = run_benchmark("[3] Zkne HW (scalar cryp)", aes128_ecb_encrypt_zkne,  key, plaintext);
  {
    uint32_t s = (cyc_soft * 10u) / cyc_zkne;
    neorv32_uart0_printf("  [3] vs [1] speedup : %u.", s / 10);
    neorv32_uart0_printf("%ux\n", s % 10);
  }
#else
  neorv32_uart0_puts("[3] Zkne HW  skipped (MARCH lacks zkne)\n");
#endif

    /* --- Bit-sliced AES benchmark (32 blocks in parallel) --- */
  {
    /* Build input: 32 copies of the same plaintext */
    static uint8_t bs_in [32][16];
    static uint8_t bs_out[32][16];
    for (int j = 0; j < 32; j++)
      for (int k = 0; k < 16; k++)
        bs_in[j][k] = plaintext[k];

    const uint32_t N_BS = 100; /* 100 calls × 32 blocks = 3200 blocks */
    uint64_t ts0 = neorv32_cpu_get_cycle();
    for (uint32_t i = 0; i < N_BS; i++) {
      aes128_ecb_encrypt_bs(key, (const uint8_t (*)[16])bs_in, bs_out);
    }
    uint64_t ts1 = neorv32_cpu_get_cycle();

    uint32_t total_cycles   = (uint32_t)(ts1 - ts0);
    uint32_t cyc_bs         = total_cycles / (N_BS * 32u); /* per block */
    uint32_t f_clk          = NEORV32_SYSINFO->CLK;
    uint64_t bits           = (uint64_t)N_BS * 32u * 128u;
    uint64_t tp_bps         = (bits * (uint64_t)f_clk) / (uint64_t)total_cycles;
    uint32_t tp_kbps        = (uint32_t)(tp_bps / 1000u);

    neorv32_uart0_puts("[4] Bit-sliced (32 blk)  ");
    neorv32_uart0_printf("Cycles/blk : %u\n", cyc_bs);
    neorv32_uart0_printf("Throughput : %u kbit/s\n", tp_kbps);
    uint32_t s = (cyc_soft * 10u) / cyc_bs;
    neorv32_uart0_printf("  [4] vs [1] speedup : %u.", s / 10);
    neorv32_uart0_printf("%ux\n", s % 10);

    /* [4b] Optimised: O2 sbox + memcpy-free MixCol */
    ts0 = neorv32_cpu_get_cycle();
    for (uint32_t i = 0; i < N_BS; i++) {
      aes128_ecb_encrypt_bs_opt(key, (const uint8_t (*)[16])bs_in, bs_out);
    }
    ts1 = neorv32_cpu_get_cycle();
    total_cycles  = (uint32_t)(ts1 - ts0);
    uint32_t cyc_bsopt = total_cycles / (N_BS * 32u);
    tp_bps   = ((uint64_t)N_BS * 32u * 128u * (uint64_t)f_clk) / (uint64_t)total_cycles;
    tp_kbps  = (uint32_t)(tp_bps / 1000u);
    neorv32_uart0_puts("[4b] BS-opt (O2+no-mcpy) ");
    neorv32_uart0_printf("Cycles/blk : %u\n", cyc_bsopt);
    neorv32_uart0_printf("Throughput : %u kbit/s\n", tp_kbps);
    {
      uint32_t s4b = (cyc_bs * 10u) / cyc_bsopt;
      neorv32_uart0_printf("  [4b] vs [4] speedup : %u.", s4b / 10);
      neorv32_uart0_printf("%ux  (O2 sbox + no memcpy)\n", s4b % 10);
    }
  }

  /* --- AES WP + Zba [8]: word S-box → sh2add for SubBytes table indices ---
   * Difference vs [2]: SubBytes uses uint32_t S-box (sh2add) vs uint8_t (add).
   * Both have identical Zbb (rori/andn) in MixColumns.
   * Savings: 4 lookups × 4 cols × 10 rounds = 160 sh2add per block.
   * On in-order NEORV32: each slli eliminated saves ~1 pipeline slot.
   */
#ifdef __riscv_zba
  {
    uint32_t cyc_wpz = run_benchmark("[8] AES WP+Zba (sh2add) ", aes128_ecb_encrypt_wp_zba, key, plaintext);
    {
      uint32_t s = (cyc_soft * 10u) / cyc_wpz;
      neorv32_uart0_printf("  [8] vs [1] speedup : %u.", s / 10);
      neorv32_uart0_printf("%ux\n", s % 10);
    }
    {
      uint32_t s = (cyc_wp * 10u) / cyc_wpz;
      neorv32_uart0_printf("  [8] vs [2] speedup : %u.", s / 10);
      neorv32_uart0_printf("%ux  (sh2add over add for SubBytes)\n", s % 10);
    }
  }
#else
  neorv32_uart0_puts("[8] AES WP+Zba   skipped (MARCH lacks zba)\n");
#endif
}


/**********************************************************************//**
 * MKV-128 correctness check + benchmark — reserved, not called.
 **************************************************************************/
#if 0
static void mkv_benchmark(void) {
  /* 128-bit key (first 16 bytes used; 16-byte variant → 7 rounds) */
  const uint8_t mkv_key[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
  };
  const uint8_t mkv_plain[16] = {
    0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
    0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00
  };

  neorv32_uart0_puts("\n--- MKV-128 word-parallel (tableless MixWords) ---\n");

  /* --- Correctness check --- */
  uint8_t mkv_enc_wp [16], mkv_enc_wpz[16];
  uint8_t mkv_dec_wp [16];

  mkv_wp_bench    (mkv_key, mkv_plain, mkv_enc_wp);
  mkv_wp_bench_zba(mkv_key, mkv_plain, mkv_enc_wpz);

  /* Decrypt via pre-keyed path */
  {
    mkv_wp_ctx_t ctx;
    mkv_wp_init(&ctx, MKV_ROUNDS_128, mkv_key);
    mkv_wp_decrypt(&ctx, mkv_enc_wp, mkv_dec_wp);
  }

  /* wp vs wp_zba must match (only sbox table type differs) */
  int ok_zba_eq = 1;
  for (int i = 0; i < 16; i++)
    if (mkv_enc_wp[i] != mkv_enc_wpz[i]) ok_zba_eq = 0;

  /* decrypt must recover plaintext */
  int ok_rttrip = 1;
  for (int i = 0; i < 16; i++)
    if (mkv_dec_wp[i] != mkv_plain[i]) ok_rttrip = 0;

  print_hex("MKV plain   : ", mkv_plain,   16);
  print_hex("MKV cipher  : ", mkv_enc_wp,  16);
  print_hex("MKV decrypted:", mkv_dec_wp,  16);
  neorv32_uart0_puts(ok_zba_eq  ? "MKV wp==wpZ : PASS\n" : "MKV wp==wpZ : FAIL (sbox32 mismatch)\n");
  neorv32_uart0_puts(ok_rttrip  ? "MKV decrypt : PASS\n" : "MKV decrypt : FAIL (round-trip)\n");

  /* --- Benchmark: key schedule included (same as other ciphers) --- */
  neorv32_uart0_puts("\n--- Benchmark (1000 blocks each) ---\n");
  uint32_t cyc_mkv = run_benchmark("[9] MKV-128 wp  (Zbb)   ",
                                    mkv_wp_bench, mkv_key, mkv_plain);

#ifdef __riscv_zba
  uint32_t cyc_mkvz = run_benchmark("[10] MKV-128 wp+Zba     ",
                                     mkv_wp_bench_zba, mkv_key, mkv_plain);
  {
    uint32_t s = (cyc_mkv * 10u) / cyc_mkvz;
    neorv32_uart0_printf("  [10] vs [9] speedup : %u.", s / 10);
    neorv32_uart0_printf("%ux  (sh2add for SubCells)\n", s % 10);
  }
#else
  neorv32_uart0_puts("[10] MKV wp+Zba  skipped (MARCH lacks zba)\n");
#endif

  /* --- [11] MKV fully-optimised: always_inline + nomul + Zba + Zbkb ---
   *
   * Three compiler-level fixes stacked:
   *  A) always_inline on xtime_w/subcells4/mix_col_fwd
   *     Without -Os refuses to inline 'static inline' → 4×jal overhead per column.
   *     Saves: ~20-30 extra cycles per mix_col_fwd call.
   *
   *  B) xtime_w_nomul: 0x2B mult expanded as shifts+XOR (3 slli + 3 xor = 6 insns)
   *     On NEORV32 with sequential multiplier: mul = up to 32 stall cycles.
   *     On NEORV32 with FAST_MUL: mul = ~2-3 cycles → shift version slower.
   *     Net: beneficial only for slow-MUL targets.
   *
   *  C) pack_state_zbkb: 2× packh + 1× pack per word = 7 insns vs 10 insns.
   *     Zbkb is already in MARCH but GCC didn't recognise the original pattern.
   *     Saves ~12 insns per pack_state call.
   */
  uint32_t cyc_opt = run_benchmark("[11] MKV opt (nomul+Zbkb)",
                                    mkv_wp_bench_opt, mkv_key, mkv_plain);
  {
    uint32_t s = (cyc_mkv * 10u) / cyc_opt;
    neorv32_uart0_printf("  [11] vs [9]  speedup : %u.", s / 10);
    neorv32_uart0_printf("%ux  (always_inline+nomul+packh)\n", s % 10);
  }

  /* Note: run_benchmark uses 16-byte key argument but mkv uses full key width.
   * All benchmarks [9]-[11] include key schedule in every call (worst-case latency). */
  (void)cyc_opt;
}
#endif /* 0 */


/**********************************************************************//**
 * Micro-benchmark: isolate the cost of andn (a & ~b) and rori (rotate).
 *
 * Each test runs N iterations of a tight dependency chain using only that
 * one operation. A dependency chain is used so GCC cannot hoist or
 * re-order the operations. The dummy XOR with a constant at the end of
 * each step keeps the accumulator alive and forces real computation.
 *
 * With Zbb compiled in:
 *   andn: 1 instruction/iter   (andn rd, rs1, rs2)
 *   rori: 1 instruction/iter   (rori rd, rs1, imm)
 *
 * Without Zbb (rv32imc baseline):
 *   andn → not + and  = 2 instructions/iter  → ~2× slower
 *   rori → srli + slli + or = 3 instructions/iter → ~3× slower
 *
 * Expected cycle ratios (no pipeline hazard differences assumed):
 *   andn: ~2× (without vs with Zbb)
 *   rori: ~3× (without vs with Zbb)
 **************************************************************************/
static void bitmanip_microbench(void) {
  const uint32_t N = 100000u;
  uint32_t a, b, cyc;
  uint64_t t0, t1;

  neorv32_uart0_puts("\n--- Bitmanip micro-benchmark (100k iterations each) ---\n");

#ifdef __riscv_zbb
  neorv32_uart0_puts("Compiled with Zbb: andn + rori available\n");
#else
  neorv32_uart0_puts("Compiled WITHOUT Zbb: andn = not+and, rori = srli+slli+or\n");
#endif

  /*
   * Use runtime seed from cycle counter so GCC cannot constant-fold the loop.
   * Print final accumulator so GCC cannot dead-code-eliminate the loop body.
   */

  /* ---- (A) andn: measure  a = a & ~b  per iteration ---- */
  /* seed from runtime value — prevents constant folding */
  a = (uint32_t)neorv32_cpu_get_cycle() | 1u;
  b = a ^ 0xDEADBEEFu;
  t0 = neorv32_cpu_get_cycle();
  for (uint32_t i = 0; i < N; i++) {
    a = a & ~b;          /* GCC+Zbb: andn;  no-Zbb: not+and */
    b = b ^ a ^ 0xABu;  /* dependency: next b depends on a */
  }
  t1 = neorv32_cpu_get_cycle();
  cyc = (uint32_t)(t1 - t0);
  neorv32_uart0_printf("andn (a & ~b) : %u cycles total = ", cyc);
  neorv32_uart0_printf("%u cycles/iter  [chk=%x]\n", cyc / N, a);

  /* ---- (B) rori: measure  a = ROR(a, 8)  per iteration ---- */
  a = (uint32_t)neorv32_cpu_get_cycle() | 1u;
  t0 = neorv32_cpu_get_cycle();
  for (uint32_t i = 0; i < N; i++) {
    a = (a >> 8) | (a << 24);  /* GCC+Zbb: rori 8;  no-Zbb: srli+slli+or */
  }
  t1 = neorv32_cpu_get_cycle();
  cyc = (uint32_t)(t1 - t0);
  neorv32_uart0_printf("rori (ror 8)  : %u cycles total = ", cyc);
  neorv32_uart0_printf("%u cycles/iter  [chk=%x]\n", cyc / N, a);

  /* ---- (C) sh2add: uint32_t table lookup vs uint8_t table lookup ----------
   * uint32_t tbl[i]: address = base + i*4 → GCC+Zba: sh2add  (2 instr: sh2add+lw)
   *                                         No  Zba:  slli+add+lw (3 instr)
   * uint8_t  tbl[i]: address = base + i*1 → always add+lbu (2 instr, Zba-immune)
   *
   * Expected result:
   *   With Zba:    cyc_u32 ≈ cyc_u8   (sh2add cost = add cost)
   *   Without Zba: cyc_u32 > cyc_u8   (extra slli per iteration)
   * Difference = overhead eliminated by sh2add.
   * -----------------------------------------------------------------------*/
#ifdef __riscv_zba
  neorv32_uart0_puts("Compiled with Zba: sh2add available\n");
#else
  neorv32_uart0_puts("Compiled WITHOUT Zba: uint32_t lookup = slli+add+lw\n");
#endif
  {
    /* Small 16-entry tables — size doesn't matter, only element width does */
    static const uint32_t _t32[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    static const uint8_t  _t8 [16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint32_t sum32 = 0, sum8 = 0, cyc32, cyc8;

    /* uint32_t table: GCC+Zba emits sh2add; without Zba emits slli+add */
    a = (uint32_t)neorv32_cpu_get_cycle() | 1u;
    t0 = neorv32_cpu_get_cycle();
    for (uint32_t i = 0; i < N; i++) { sum32 ^= _t32[(i ^ a) & 0xfu]; }
    t1 = neorv32_cpu_get_cycle();
    cyc32 = (uint32_t)(t1 - t0);

    /* uint8_t table: always lbu, no scaling regardless of Zba */
    a = (uint32_t)neorv32_cpu_get_cycle() | 1u;
    t0 = neorv32_cpu_get_cycle();
    for (uint32_t i = 0; i < N; i++) { sum8  ^= _t8 [(i ^ a) & 0xfu]; }
    t1 = neorv32_cpu_get_cycle();
    cyc8 = (uint32_t)(t1 - t0);

    neorv32_uart0_printf("sh2add uint32[]: %u cycles total = ", cyc32);
    neorv32_uart0_printf("%u cycles/iter  [chk=%x]\n", cyc32 / N, sum32);
    neorv32_uart0_printf("add    uint8 []: %u cycles total = ", cyc8);
    neorv32_uart0_printf("%u cycles/iter  [chk=%x]\n", cyc8  / N, sum8);
    if (cyc32 < cyc8) {
      neorv32_uart0_printf("  sh2add faster by %u cycles/iter (Zba benefit)\n",
                           (cyc8 - cyc32) / N);
    } else if (cyc32 > cyc8) {
      neorv32_uart0_printf("  uint32[] overhead: %u cycles/iter (no sh2add)\n",
                           (cyc32 - cyc8) / N);
    } else {
      neorv32_uart0_puts("  uint32[] == uint8[] cost (sh2add matched add)\n");
    }
  }

  /* ---- (C) baseline: plain XOR, 1 instr/iter ---- */
  a = (uint32_t)neorv32_cpu_get_cycle() | 1u;
  t0 = neorv32_cpu_get_cycle();
  for (uint32_t i = 0; i < N; i++) {
    a = a ^ b;  /* xor: 1 instruction always, no Zbb dependency */
    b = b ^ a;  /* dependency chain to prevent loop collapsing  */
  }
  t1 = neorv32_cpu_get_cycle();
  cyc = (uint32_t)(t1 - t0);
  neorv32_uart0_printf("xor  (baseline): %u cycles total = ", cyc);
  neorv32_uart0_printf("%u cycles/iter  [chk=%x]\n", cyc / N, a);
}


/**********************************************************************//**
 * Main function: simple AES-128 ECB encrypt/decrypt demo.
 **************************************************************************/
int main(void) {

  // Capture all exceptions and give debug info via UART
  neorv32_rte_setup();

  // Setup UART at default baud rate, no interrupts
  neorv32_uart0_setup(BAUD_RATE, 0);

  // Wait for user to open terminal
  neorv32_uart0_puts("\nPress any key to start AES demo...\n");
  while (neorv32_uart0_char_received() == 0); // block until a character is received
  neorv32_uart0_getc(); // consume the character

  neorv32_uart0_puts("\nNEORV32 AES demo (tiny-AES-c, ECB-128)\n");

  // AES-128 test vector from NIST SP 800-38A (first block)
  const uint8_t key[16] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
  };

  const uint8_t plaintext[16] = {
    0x6b, 0xc1, 0xbe, 0xe2,
    0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11,
    0x73, 0x93, 0x17, 0x2a
  };

  uint8_t ciphertext[16];
  uint8_t decrypted[16];
  uint8_t cipher_wp[16];
  uint8_t cipher_zkne[16];
  uint8_t cipher_bs[16];
  uint8_t cipher_bs_opt[16];
  uint8_t cipher_wp_zba[16];

  // Soft AES encrypt/decrypt
  aes128_ecb_encrypt_block(key, plaintext, ciphertext);
  aes128_ecb_decrypt_block(key, ciphertext, decrypted);

  // Word-parallel AES
  aes128_ecb_encrypt_wp(key, plaintext, cipher_wp);

  // Word-parallel AES + Zba (sh2add for SubBytes table indexing)
  aes128_ecb_encrypt_wp_zba(key, plaintext, cipher_wp_zba);

  // Zkne AES
  aes128_ecb_encrypt_zkne(key, plaintext, cipher_zkne);

  // Bit-sliced AES (32 parallel blocks, all same plaintext)
  {
    static uint8_t bs_in [32][16];
    static uint8_t bs_out[32][16];
    for (int j = 0; j < 32; j++)
      for (int k = 0; k < 16; k++)
        bs_in[j][k] = plaintext[k];
    aes128_ecb_encrypt_bs(key, (const uint8_t (*)[16])bs_in, bs_out);
    for (int k = 0; k < 16; k++) cipher_bs[k] = bs_out[0][k];
    aes128_ecb_encrypt_bs_opt(key, (const uint8_t (*)[16])bs_in, bs_out);
    for (int k = 0; k < 16; k++) cipher_bs_opt[k] = bs_out[0][k];
  }

  // Print results
  print_hex("Plain       : ", plaintext,    16);
  print_hex("Cipher (sw) : ", ciphertext,   16);
  print_hex("Decr   (sw) : ", decrypted,    16);
  print_hex("Cipher (wp) : ", cipher_wp,      16);
  print_hex("Cipher(wpZ) : ", cipher_wp_zba,  16);
  print_hex("Cipher(zkne): ", cipher_zkne,    16);
  print_hex("Cipher  (bs): ", cipher_bs,     16);
  print_hex("Cipher(bsOp): ", cipher_bs_opt,  16);

  // Correctness checks
  int ok_wp   = 1, ok_zkne = 1, ok_bs = 1, ok_wp_zba = 1, ok_bs_opt = 1;
  for (int i = 0; i < 16; i++) {
    if (cipher_wp    [i] != ciphertext[i]) ok_wp     = 0;
    if (cipher_zkne  [i] != ciphertext[i]) ok_zkne   = 0;
    if (cipher_bs    [i] != ciphertext[i]) ok_bs     = 0;
    if (cipher_wp_zba[i] != ciphertext[i]) ok_wp_zba = 0;
    if (cipher_bs_opt[i] != ciphertext[i]) ok_bs_opt = 0;
  }
  neorv32_uart0_puts(ok_wp     ? "WP   verify: PASS\n" : "WP   verify: FAIL\n");
  neorv32_uart0_puts(ok_wp_zba ? "WPZ  verify: PASS\n" : "WPZ  verify: FAIL\n");
  neorv32_uart0_puts(ok_zkne   ? "Zkne verify: PASS\n" : "Zkne verify: FAIL\n");
  neorv32_uart0_puts(ok_bs     ? "BS   verify: PASS\n" : "BS   verify: FAIL (debug needed)\n");
  neorv32_uart0_puts(ok_bs_opt ? "BSop verify: PASS\n" : "BSop verify: FAIL (O2 sbox bug?)\n");

  // Benchmark AES performance
  aes_benchmark();

  // Micro-benchmark: andn and rori in isolation
  bitmanip_microbench();

  neorv32_uart0_puts("Done.\n");

  return 0;
}
