/*
 * Host-side test: verify bit-sliced S-box against the standard AES S-box LUT.
 * Compile: gcc -O2 -o test_sbox test_sbox.c && ./test_sbox
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Known AES S-box */
static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Override ANDN for host (no Zbb) */
#define ANDN(a, b) ((a) & ~(b))

/* Copy the bs_sbox function exactly from aes_bs.c */
static void bs_sbox(uint32_t q[8])
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

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

int main(void)
{
    int errors = 0;

    /* Test all 256 S-box values using bit-sliced approach.
     * We pack all 256 values into 8 batches of 32. */
    for (int batch = 0; batch < 8; batch++) {
        uint32_t q[8] = {0};

        /* Pack 32 values into bit-planes */
        for (int j = 0; j < 32; j++) {
            uint8_t val = batch * 32 + j;
            for (int b = 0; b < 8; b++) {
                if ((val >> b) & 1)
                    q[b] |= (1u << j);
            }
        }

        /* Apply S-box */
        bs_sbox(q);

        /* Unpack and verify */
        for (int j = 0; j < 32; j++) {
            uint8_t got = 0;
            for (int b = 0; b < 8; b++) {
                if ((q[b] >> j) & 1)
                    got |= (1u << b);
            }
            uint8_t input = batch * 32 + j;
            uint8_t expected = aes_sbox[input];
            if (got != expected) {
                if (errors < 20)
                    printf("FAIL: S-box[0x%02x] = 0x%02x, expected 0x%02x (diff=0x%02x)\n",
                           input, got, expected, got ^ expected);
                errors++;
            }
        }
    }

    if (errors == 0)
        printf("ALL 256 S-box values PASS!\n");
    else
        printf("\n%d / 256 S-box values FAILED\n", errors);

    return errors ? 1 : 0;
}
