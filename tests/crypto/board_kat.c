/* On-target KAT for all 17 benchmark cryptographic paths. */
#include <neorv32.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"
#include "aes_wp.h"
#include "aes_bm.h"
#include "aes_ttable.h"
#include "mkv_wp.h"
#include "mkv_ttable.h"
#include "magma.h"
#include "present.h"
#include "prince.h"
#include "simon.h"
#include "speck_fast.h"
#include "speck.h"
#include "speck128.h"
#include "lea.h"
#include "chacha.h"

static unsigned failures;

static uint8_t digit(char c) {
  return (uint8_t)((c <= '9') ? c - '0' : (c | 32) - 'a' + 10);
}

static void from_hex(const char *src, uint8_t *dst) {
  for (unsigned i = 0; src[2 * i]; i++) {
    dst[i] = (uint8_t)((digit(src[2 * i]) << 4) | digit(src[2 * i + 1]));
  }
}

static void check(const char *name, const uint8_t *actual,
                  const char *expected_hex, unsigned size) {
  uint8_t expected[64];
  from_hex(expected_hex, expected);
  int failed = memcmp(actual, expected, size) != 0;
  failures += (unsigned)failed;
  neorv32_uart0_puts(name);
  neorv32_uart0_puts(failed ? " FAIL\n" : " PASS\n");
}

int main(void) {
  uint8_t key[32] = {0};
  uint8_t input[16] = {0};
  uint8_t output[16] = {0};
  neorv32_rte_setup();
  neorv32_uart0_setup(19200, 0);
  neorv32_uart0_puts("BOARD_KAT START\n");

  from_hex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", key);
  from_hex("fedcba9876543210", input);
  magma_ctx_t magma;
  magma_init(&magma, key);
  magma_encrypt_prerot(&magma, input, output);
  check("Magma-Prerot", output, "4ee901e5c2d8ca3d", 8);
  magma_encrypt_rori(&magma, input, output);
  check("Magma-Rori", output, "4ee901e5c2d8ca3d", 8);
  from_hex("4ee901e5c2d8ca3d", input);
  magma_decrypt_prerot(&magma, input, output);
  check("Magma-decrypt", output, "fedcba9876543210", 8);

  const char *present_keys[4] = {
    "00000000000000000000", "ffffffffffffffffffff",
    "00000000000000000000", "ffffffffffffffffffff"
  };
  const char *present_inputs[4] = {
    "0000000000000000", "0000000000000000",
    "ffffffffffffffff", "ffffffffffffffff"
  };
  const char *present_outputs[4] = {
    "5579c1387b228445", "e72c46c0f5945049",
    "a112ffc72f68417b", "3333dcd3213210d2"
  };
  present_ctx_t present;
  for (unsigned i = 0; i < 4; i++) {
    from_hex(present_keys[i], key);
    from_hex(present_inputs[i], input);
    present_init(&present, key);
    present_encrypt(&present, input, output);
    check("PRESENT-80", output, present_outputs[i], 8);
  }

  const char *prince_keys[5] = {
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    "ffffffffffffffff0000000000000000",
    "0000000000000000ffffffffffffffff",
    "0000000000000000fedcba9876543210"
  };
  const char *prince_inputs[5] = {
    "0000000000000000", "ffffffffffffffff", "0000000000000000",
    "0000000000000000", "0123456789abcdef"
  };
  const char *prince_outputs[5] = {
    "818665aa0d02dfda", "604ae6ca03c20ada", "9fb51935fc3df524",
    "78a54cbe737bb7ef", "ae25ad3ca8fa9ccf"
  };
  prince_ctx_t prince;
  for (unsigned i = 0; i < 5; i++) {
    from_hex(prince_keys[i], key);
    from_hex(prince_inputs[i], input);
    prince_init(&prince, key);
    prince_encrypt(&prince, input, output);
    check("PRINCE", output, prince_outputs[i], 8);
  }

  from_hex("0001020308090a0b1011121318191a1b", key);
  from_hex("756e64206c696b65", input);
  simon_ctx_t simon;
  simon_init(&simon, key);
  simon_encrypt(&simon, input, output);
  check("Simon-64/128", output, "7aa0dfb920fcc844", 8);

  from_hex("2d4375747465723b", input);
  speck_fast_bench(key, input, output);
  check("Speck-64-Fast", output, "8b024e4548a56f8c", 8);

  from_hex("000102030405060708090a0b0c0d0e0f", key);
  from_hex("206d616465206974206571756976616c", input);
  speck128_ctx_t speck128;
  speck128_init(&speck128, key);
  speck128_encrypt(&speck128, input, output);
  check("Speck-128/128", output, "180d575cdffe60786532787951985da6", 16);

  from_hex("0f1e2d3c4b5a69788796a5b4c3d2e1f0", key);
  from_hex("101112131415161718191a1b1c1d1e1f", input);
  lea_ctx_t lea;
  lea_init(&lea, key);
  lea_encrypt(&lea, input, output);
  check("LEA-128", output, "9fc84e3528c6c6185532c7a704648bfd", 16);

  from_hex("2b7e151628aed2a6abf7158809cf4f3c", key);
  from_hex("6bc1bee22e409f96e93d7e117393172a", input);
  struct AES_ctx aes;
  AES_init_ctx(&aes, key);
  memcpy(output, input, 16);
  AES_ECB_encrypt(&aes, output);
  check("AES-Soft", output, "3ad77bb40d7a3660a89ecaf32466ef97", 16);
  aes128_ecb_encrypt_wp(key, input, output);
  check("AES-WP", output, "3ad77bb40d7a3660a89ecaf32466ef97", 16);
  aes_bm_bench(key, input, output);
  check("AES-WordBM", output, "3ad77bb40d7a3660a89ecaf32466ef97", 16);
  aes_ttable_init();
  aes_ttable_bench(key, input, output);
  check("AES-TTable", output, "3ad77bb40d7a3660a89ecaf32466ef97", 16);

  uint8_t mkv_selftest = (uint8_t)mkv_wp_selftest();
  check("MKV-selftest", &mkv_selftest, "2f", 1);
  from_hex("000102030405060708090a0b0c0d0e0f", key);
  from_hex("ffeeddccbbaa99887766554433221100", input);
  mkv_wp_ctx_t mkv;
  mkv_wp_init(&mkv, MKV_ROUNDS_128, key);
  mkv_wp_encrypt(&mkv, input, output);
  check("MKV-WP", output, "f2795ecba8f4d887f539ee8d8df1141d", 16);
  mkv_wp_encrypt_opt(&mkv, input, output);
  check("MKV-Opt", output, "f2795ecba8f4d887f539ee8d8df1141d", 16);
  mkv_ttable_init();
  mkv_ttable_keysched(&mkv, MKV_ROUNDS_128, key);
  mkv_ttable_encrypt(&mkv, input, output);
  check("MKV-TTable", output, "f2795ecba8f4d887f539ee8d8df1141d", 16);

  from_hex("0001020308090a0b1011121318191a1b", key);
  from_hex("2d4375747465723b", input);
  speck_ctx_t speck;
  speck_init(&speck, key);
  speck_encrypt(&speck, input, output);
  check("Speck-64-Std", output, "8b024e4548a56f8c", 8);

  const uint32_t chacha_state[16] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
    1, 0x09000000, 0x4a000000, 0
  };
  uint32_t chacha_result[16];
  chacha20_block(chacha_result, chacha_state);
  check("ChaCha20-core", (const uint8_t *)chacha_result,
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e", 64);

  neorv32_uart0_puts(failures ? "BOARD_KAT FAIL\n" : "BOARD_KAT PASS\n");
  while (neorv32_uart0_tx_busy()) {}
  __asm__ volatile("li t0,0xFFE00000; jr t0");
  __builtin_unreachable();
}
