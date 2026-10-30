#ifndef AES_BS_H
#define AES_BS_H

/*
 * Full Bit-Sliced AES-128 ECB — 32 blocks processed in parallel on RV32.
 *
 * Architecture overview
 * ---------------------
 * Standard AES operates on 1 block at a time with byte-oriented state.
 * Bit-sliced AES represents the state differently:
 *
 *   Standard:     state[byte_index]         = 1 byte from 1 block
 *   Bit-sliced:   bs_state[bit_index]       = 1 bit from each of 32 blocks
 *                 bs_state[bit_index] is a uint32_t whose bit j = bit bit_index of block j
 *
 * This allows 32 blocks to be encrypted simultaneously at the cost of 1-block
 * worth of operations, amortizing overhead and enabling SIMD-like parallelism
 * without any vector ISA extension.
 *
 * Zbb (Bitmanip) benefit — WHERE andn is used
 * ---------------------------------------------
 * The AES S-box is implemented as a Boolean circuit (Boyar-Peralta 2012):
 *   - 17 AND gates (nonlinear)
 *   - ~83 XOR gates (linear)
 *   - NO table lookups → eliminates S-box RAM bottleneck
 *
 * The AES affine transform adds the constant 0x63 = 0110_0011, which INVERTS
 * bits 0, 1, 5, 6 of each output byte. In the bit-sliced circuit, these
 * 4 output bit-planes are produced in COMPLEMENTED form (using ~ / NOT).
 *
 * When a later operation writes  (NOT x) & y, GCC+Zbb compiles this as:
 *
 *   Without Zbb:   not reg_x; and reg_y, reg_x   = 2 instructions
 *   With    Zbb:   andn reg_y, reg_x              = 1 instruction (saves 1)
 *
 * Further, inside the Boyar-Peralta bottom layer, several sub-expressions
 * involve   a & ~b  patterns which GCC+Zbb emits as andn without any
 * extra help from the programmer:
 *
 *   t26 = t21 & t23  (plain AND — 1 instr either way)
 *   ... but later products where one operand was computed as ~expr
 *   naturally expose the andn pattern to the compiler.
 *
 * andn count per S-box call: ~4 (from the 4 NOT output planes used in AND)
 * S-box calls: 16 bytes × 10 rounds = 160 per block
 * andn savings per block: 160 × 4 = 640 instructions saved with Zbb.
 *
 * Throughput
 * ----------
 * Bit-sliced encrypts 32 blocks per call.
 * cycles_per_single_block ≈ total_cycles / 32
 * Expected: significantly fewer cycles/block than single-block soft AES.
 */

#include <stdint.h>

/*
 * Encrypt exactly 32 AES-128 blocks (512 bytes) simultaneously.
 *
 * key[16]       : AES-128 key (same key for all 32 blocks)
 * in[32][16]    : 32 plaintext blocks
 * out[32][16]   : 32 ciphertext blocks
 */
void aes128_ecb_encrypt_bs(const uint8_t  key[16],
                            const uint8_t  in[32][16],
                                  uint8_t  out[32][16]);

/*
 * Optimised variant combining:
 *   A) bs_sbox compiled with -O2 (fewer register spills than -Os)
 *   B) memcpy-free MixColumns (pointer alias instead of array copy)
 */
void aes128_ecb_encrypt_bs_opt(const uint8_t  key[16],
                                const uint8_t  in[32][16],
                                      uint8_t  out[32][16]);

#endif /* AES_BS_H */
