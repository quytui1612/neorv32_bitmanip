#ifndef AES_BM_H
#define AES_BM_H
#include <stdint.h>

/* AES-BM: word-parallel, unrolled, rori+andn optimized */
void aes_bm_encrypt(const uint8_t in[16], uint8_t out[16]);
void aes_bm_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/* Baseline: tiny-AES-c byte LUT */
void aes_baseline_bench(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#endif
