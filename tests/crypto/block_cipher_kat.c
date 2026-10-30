/* Host known-answer test for all block-cipher paths used by hello_world.
 * Build with the algorithm C files listed in the benchmark makefile and
 * tiny-AES-c/aes.c. Run once normally and once with
 * -DCIPHER_TEST_XPERM4 to emulate the RISC-V nibble lookup branches.
 * A mismatch exits with a nonzero status.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"
#include "aes_wp.h"
#include "aes_bm.h"
#include "aes_ttable.h"
#include "mkv_wp.h"
#include "mkv_ttable.h"
#include "magma.h"
#include "speck.h"
#include "speck_fast.h"
#include "speck128.h"
#include "lea.h"
#include "present.h"
#include "simon.h"
#include "prince.h"
#include "chacha.h"
static uint8_t hex_digit(char c){return (uint8_t)(c<='9'?c-'0':(c|32)-'a'+10);}
static void h(const char*s,uint8_t*b){for(size_t i=0;i<strlen(s)/2;i++)b[i]=(uint8_t)((hex_digit(s[2*i])<<4)|hex_digit(s[2*i+1]));}
static int failures;
static void test(const char*n,const uint8_t*out,const char*exp,size_t len){uint8_t e[64]={0};h(exp,e);int fail=memcmp(out,e,len)!=0;failures+=fail;printf("%-20s %s got=",n,fail?"FAIL":"PASS");for(size_t i=0;i<len;i++)printf("%02x",out[i]);putchar('\n');}
int main(void){uint8_t key[32]={0},in[64]={0},out[64]={0};
 h("2b7e151628aed2a6abf7158809cf4f3c",key);h("6bc1bee22e409f96e93d7e117393172a",in);
 struct AES_ctx a;AES_init_ctx(&a,key);memcpy(out,in,16);AES_ECB_encrypt(&a,out);test("AES soft",out,"3ad77bb40d7a3660a89ecaf32466ef97",16);
 aes128_ecb_encrypt_wp(key,in,out);test("AES WP",out,"3ad77bb40d7a3660a89ecaf32466ef97",16);
 aes_bm_bench(key,in,out);test("AES WordBM",out,"3ad77bb40d7a3660a89ecaf32466ef97",16);
 aes_ttable_init();aes_ttable_bench(key,in,out);test("AES TTable",out,"3ad77bb40d7a3660a89ecaf32466ef97",16);
 int mkv_bits=mkv_wp_selftest();failures+=(mkv_bits!=0x2f);printf("MKV selftest bits=%02x expected=2f %s\n",mkv_bits,mkv_bits==0x2f?"PASS":"FAIL");
 h("000102030405060708090a0b0c0d0e0f",key);h("ffeeddccbbaa99887766554433221100",in);
 mkv_wp_ctx_t m;mkv_wp_init(&m,MKV_ROUNDS_128,key);mkv_wp_encrypt(&m,in,out);test("MKV WP",out,"f2795ecba8f4d887f539ee8d8df1141d",16);
 mkv_wp_encrypt_opt(&m,in,out);test("MKV Opt",out,"f2795ecba8f4d887f539ee8d8df1141d",16);
 mkv_ttable_init();mkv_ttable_keysched(&m,MKV_ROUNDS_128,key);mkv_ttable_encrypt(&m,in,out);test("MKV TTable",out,"f2795ecba8f4d887f539ee8d8df1141d",16);
 h("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",key);h("fedcba9876543210",in);
 magma_ctx_t g;magma_init(&g,key);magma_encrypt_prerot(&g,in,out);test("Magma prerot",out,"4ee901e5c2d8ca3d",8);magma_encrypt_rori(&g,in,out);test("Magma rori",out,"4ee901e5c2d8ca3d",8);
 memset(key,0,sizeof key);memset(in,0,sizeof in);present_ctx_t p;present_init(&p,key);present_encrypt(&p,in,out);test("PRESENT-80",out,"5579c1387b228445",8);
 prince_ctx_t pr;prince_init(&pr,key);prince_encrypt(&pr,in,out);test("PRINCE",out,"818665aa0d02dfda",8);
 h("0001020308090a0b1011121318191a1b",key);h("2d4375747465723b",in);speck_ctx_t s;speck_init(&s,key);speck_encrypt(&s,in,out);test("Speck64 std",out,"8b024e4548a56f8c",8);speck_fast_bench(key,in,out);test("Speck64 fast",out,"8b024e4548a56f8c",8);
 h("756e64206c696b65",in);simon_ctx_t si;simon_init(&si,key);simon_encrypt(&si,in,out);test("Simon64/128",out,"7aa0dfb920fcc844",8);
 h("000102030405060708090a0b0c0d0e0f",key);h("206d616465206974206571756976616c",in);speck128_ctx_t s128;speck128_init(&s128,key);speck128_encrypt(&s128,in,out);test("Speck128/128",out,"180d575cdffe60786532787951985da6",16);
 h("0f1e2d3c4b5a69788796a5b4c3d2e1f0",key);h("101112131415161718191a1b1c1d1e1f",in);lea_ctx_t l;lea_init(&l,key);lea_encrypt(&l,in,out);test("LEA-128",out,"9fc84e3528c6c6185532c7a704648bfd",16);
 uint32_t st[16]={0x61707865,0x3320646e,0x79622d32,0x6b206574,0x03020100,0x07060504,0x0b0a0908,0x0f0e0d0c,0x13121110,0x17161514,0x1b1a1918,0x1f1e1d1c,1,0x09000000,0x4a000000,0};uint32_t res[16];chacha20_block(res,st);test("ChaCha20 core",(uint8_t*)res,"10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",64);
 const char *pk[4]={"00000000000000000000","ffffffffffffffffffff","00000000000000000000","ffffffffffffffffffff"};
 const char *pp[4]={"0000000000000000","0000000000000000","ffffffffffffffff","ffffffffffffffff"};
 const char *pc[4]={"5579c1387b228445","e72c46c0f5945049","a112ffc72f68417b","3333dcd3213210d2"};
 for(int i=0;i<4;i++){memset(key,0,32);h(pk[i],key);h(pp[i],in);present_init(&p,key);present_encrypt(&p,in,out);char label[32];sprintf(label,"PRESENT vector %d",i+1);test(label,out,pc[i],8);}
 const char *rk[5]={"00000000000000000000000000000000","00000000000000000000000000000000","ffffffffffffffff0000000000000000","0000000000000000ffffffffffffffff","0000000000000000fedcba9876543210"};
 const char *rp[5]={"0000000000000000","ffffffffffffffff","0000000000000000","0000000000000000","0123456789abcdef"};
 const char *rc[5]={"818665aa0d02dfda","604ae6ca03c20ada","9fb51935fc3df524","78a54cbe737bb7ef","ae25ad3ca8fa9ccf"};
 for(int i=0;i<5;i++){h(rk[i],key);h(rp[i],in);prince_init(&pr,key);prince_encrypt(&pr,in,out);char label[32];sprintf(label,"PRINCE vector %d",i+1);test(label,out,rc[i],8);}
 h("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",key);
 h("4ee901e5c2d8ca3d",in);magma_init(&g,key);magma_decrypt_prerot(&g,in,out);test("Magma decrypt",out,"fedcba9876543210",8);
 printf("TOTAL failures=%d\n",failures);
 return failures?1:0;}
