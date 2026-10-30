#ifndef AES_ZKNE_H
#define AES_ZKNE_H

/*
 * AES-128 ECB encrypt accelerated with RISC-V Zkne scalar crypto instructions.
 *
 * Requirements:
 *   - MARCH must include zkne (e.g. rv32imc_zkne_zknd_zicsr_zifencei).
 *   - If __riscv_zkne is not defined, falls back to tiny-AES-c software path.
 *
 * Hardware AES round instructions used (RV32 form):
 *   aes32esmi  rd, rs1, rs2, bs  - mid-round: SubBytes + ShiftRows + MixColumns (1 byte contrib)
 *   aes32esi   rd, rs1, rs2, bs  - final round: SubBytes + ShiftRows only (no MixColumns)
 */

#include <stdint.h>

/*
 * Encrypt one 16-byte block with AES-128 ECB using Zkne hardware instructions.
 * key[16]  : AES-128 key
 * in[16]   : plaintext block
 * out[16]  : ciphertext block (may alias in[])
 */
void aes128_ecb_encrypt_zkne(const uint8_t key[16],
                              const uint8_t in[16],
                              uint8_t out[16]);

/*
 * Encrypt-only: uses pre-expanded round keys (from AES_init_ctx).
 * rk must point to 44 uint32_t (= AES_ctx.RoundKey cast to uint32_t*).
 */
void aes128_ecb_encrypt_zkne_rk(const uint32_t *rk,
                                 const uint8_t in[16],
                                 uint8_t out[16]);

#endif /* AES_ZKNE_H */
