#include "stdio.h"

typedef unsigned char u8;
typedef unsigned int u32;


const unsigned int CONSTANT_0 = 0x9302ee91;
const unsigned int CONSTANT_1 = 0x1a2ad98c;
const unsigned int CONSTANT_2 = 0xad13e794;
const unsigned int CONSTANT_3 = 0x8ad8b3b2;

const unsigned int CONSTANT_4 = 0xd4da00f3;
const unsigned int CONSTANT_5 = 0x3f11fd88;
const unsigned int CONSTANT_6 = 0x22166bb9;
const unsigned int CONSTANT_7 = 0xcd187c55;

#include "PrecomputedTable128.h"
#include "MKV128.h"


void setInitialKeyState128(int keyLen, const u8 *K, u32 *Block1, u32 *Block2) {

	Block1[0] = GETU32(K);
	Block1[1] = GETU32(K + 4);
	Block1[2] = GETU32(K + 8);
	Block1[3] = GETU32(K + 12);
	if (keyLen == KeyLen128) {
		Block2[0] = Block1[0] ^ 0xFFFFFFFF;  //Nua con lai lay phu dinh
		Block2[1] = Block1[1] ^ 0xFFFFFFFF;  //Nua con lai lay phu dinh
		Block2[2] = Block1[2] ^ 0xFFFFFFFF;  //Nua con lai lay phu dinh
		Block2[3] = Block1[3] ^ 0xFFFFFFFF;  //Nua con lai lay phu dinh
	}
	if (keyLen == KeyLen192) {
		Block2[0] = GETU32(K + 16);
		Block2[1] = GETU32(K + 20);
		//Lay phu dinh hai cot con lai cua khoi 1
		Block2[2] = Block1[2] ^ 0xFFFFFFFF;
		Block2[3] = Block1[3] ^ 0xFFFFFFFF;
	}
	if (keyLen == KeyLen256) {
		Block2[0] = GETU32(K + 16);
		Block2[1] = GETU32(K + 20);
		Block2[2] = GETU32(K + 24);
		Block2[3] = GETU32(K + 28);
	}
}

int KeyExpansion128(
	int keyLen,							//Do dai khoa theo bit
	const unsigned char* MasterKey,		//Khoa chinh
	unsigned int* rKey)					//Khoa vong
{
	if (!keyLen || !MasterKey) return 0;
	u32 Block1[4], Block2[4];
	u32 tmp[4];
	int i;
	rKey[0] = GETU32(MasterKey);
	rKey[1] = GETU32(MasterKey + 4);
	rKey[2] = GETU32(MasterKey + 8);
	rKey[3] = GETU32(MasterKey + 12);
	
	int round = Round128;
	if (keyLen == KeyLen192) round = Round192;
	if (keyLen == KeyLen256) round = Round256;

	setInitialKeyState128(keyLen, MasterKey, Block1, Block2);

	for (i = 0; i < round; i++) {
		//Ham update
		//Ap dung ham F len khoi 1

		//Cong hang so CL
		Block1[0] ^= CONSTANT_0;
		Block1[1] ^= CONSTANT_1;
		Block1[2] ^= CONSTANT_2;
		Block1[3] ^= (CONSTANT_3 ^ (2 * i + 1));

		//L1S
		tmp[0] = L0[(Block1[0] >> 24) & 0xFF] ^ L1[(Block1[0] >> 16) & 0xFF] ^ L2[(Block1[0] >> 8) & 0xFF] ^ L3[Block1[0] & 0xFF];
		tmp[1] = L0[(Block1[1] >> 16) & 0xFF] ^ L1[(Block1[1] >> 8) & 0xFF] ^ L2[Block1[1] & 0xFF] ^ L3[(Block1[1] >> 24) & 0xFF];
		tmp[2] = L0[(Block1[2] >> 8) & 0xFF] ^ L1[Block1[2] & 0xFF] ^ L2[(Block1[2] >> 24) & 0xFF] ^ L3[(Block1[2] >> 16) & 0xFF];
		tmp[3] = L0[(Block1[3]) & 0xFF] ^ L1[(Block1[3] >> 24) & 0xFF] ^ L2[(Block1[3] >> 16) & 0xFF] ^ L3[(Block1[3] >> 8) & 0xFF];
		//S2
		Block1[0] = L4[(tmp[0] >> 24) & 0xFF] ^ (L4[(tmp[0] >> 16) & 0xFF] >> 8) ^ (L4[(tmp[0] >> 8) & 0xFF] >> 16) ^ (L4[tmp[0] & 0xFF] >> 24);
		Block1[1] = L4[(tmp[1] >> 24) & 0xFF] ^ (L4[(tmp[1] >> 16) & 0xFF] >> 8) ^ (L4[(tmp[1] >> 8) & 0xFF] >> 16) ^ (L4[tmp[1] & 0xFF] >> 24);
		Block1[2] = L4[(tmp[2] >> 24) & 0xFF] ^ (L4[(tmp[2] >> 16) & 0xFF] >> 8) ^ (L4[(tmp[2] >> 8) & 0xFF] >> 16) ^ (L4[tmp[2] & 0xFF] >> 24);
		Block1[3] = L4[(tmp[3] >> 24) & 0xFF] ^ (L4[(tmp[3] >> 16) & 0xFF] >> 8) ^ (L4[(tmp[3] >> 8) & 0xFF] >> 16) ^ (L4[tmp[3] & 0xFF] >> 24);
		//L2
		tmp[0] = Block1[1] ^ Block1[2] ^ Block1[3];
		tmp[1] = Block1[0] ^ Block1[2] ^ Block1[3];
		tmp[2] = Block1[0] ^ Block1[1] ^ Block1[3];
		tmp[3] = Block1[0] ^ Block1[1] ^ Block1[2];
		// 
		// 
		//L1S
		Block1[0] = L0[(tmp[0] >> 24) & 0xFF] ^ L1[(tmp[0] >> 16) & 0xFF] ^ L2[(tmp[0] >>  8) & 0xFF] ^ L3[ tmp[0]        & 0xFF];
		Block1[1] = L0[(tmp[1] >> 16) & 0xFF] ^ L1[(tmp[1] >>  8) & 0xFF] ^ L2[ tmp[1]        & 0xFF] ^ L3[(tmp[1] >> 24) & 0xFF];
		Block1[2] = L0[(tmp[2] >>  8) & 0xFF] ^ L1[ tmp[2]        & 0xFF] ^ L2[(tmp[2] >> 24) & 0xFF] ^ L3[(tmp[2] >> 16) & 0xFF];
		Block1[3] = L0[ tmp[3]        & 0xFF] ^ L1[(tmp[3] >> 24) & 0xFF] ^ L2[(tmp[3] >> 16) & 0xFF] ^ L3[(tmp[3] >>  8) & 0xFF];
		//S2
		tmp[0] = L4[(Block1[0] >> 24) & 0xFF] ^ (L4[(Block1[0] >> 16) & 0xFF] >> 8) ^ (L4[(Block1[0] >> 8) & 0xFF] >> 16) ^ (L4[Block1[0] & 0xFF] >> 24);
		tmp[1] = L4[(Block1[1] >> 24) & 0xFF] ^ (L4[(Block1[1] >> 16) & 0xFF] >> 8) ^ (L4[(Block1[1] >> 8) & 0xFF] >> 16) ^ (L4[Block1[1] & 0xFF] >> 24);
		tmp[2] = L4[(Block1[2] >> 24) & 0xFF] ^ (L4[(Block1[2] >> 16) & 0xFF] >> 8) ^ (L4[(Block1[2] >> 8) & 0xFF] >> 16) ^ (L4[Block1[2] & 0xFF] >> 24);
		tmp[3] = L4[(Block1[3] >> 24) & 0xFF] ^ (L4[(Block1[3] >> 16) & 0xFF] >> 8) ^ (L4[(Block1[3] >> 8) & 0xFF] >> 16) ^ (L4[Block1[3] & 0xFF] >> 24);
		//L2
		Block1[0] = tmp[1] ^ tmp[2] ^ tmp[3];
		Block1[1] = tmp[0] ^ tmp[2] ^ tmp[3];
		Block1[2] = tmp[0] ^ tmp[1] ^ tmp[3];
		Block1[3] = tmp[0] ^ tmp[1] ^ tmp[2];
		// 
		//Ap dung ham F len khoi 2

		//Cong hang so CR
		Block2[0] ^= CONSTANT_4;
		Block2[1] ^= CONSTANT_5;
		Block2[2] ^= CONSTANT_6;
		Block2[3] ^= (CONSTANT_7 ^ (2 * i + 2));

		//L1S
		tmp[0] = L0[(Block2[0] >> 24) & 0xFF] ^ L1[(Block2[0] >> 16) & 0xFF] ^ L2[(Block2[0] >> 8) & 0xFF] ^ L3[Block2[0] & 0xFF];
		tmp[1] = L0[(Block2[1] >> 16) & 0xFF] ^ L1[(Block2[1] >> 8) & 0xFF] ^ L2[Block2[1] & 0xFF] ^ L3[(Block2[1] >> 24) & 0xFF];
		tmp[2] = L0[(Block2[2] >> 8) & 0xFF] ^ L1[Block2[2] & 0xFF] ^ L2[(Block2[2] >> 24) & 0xFF] ^ L3[(Block2[2] >> 16) & 0xFF];
		tmp[3] = L0[Block2[3] & 0xFF] ^ L1[(Block2[3] >> 24) & 0xFF] ^ L2[(Block2[3] >> 16) & 0xFF] ^ L3[(Block2[3] >> 8) & 0xFF];
		//S2
		Block2[0] = L4[(tmp[0] >> 24) & 0xFF] ^ (L4[(tmp[0] >> 16) & 0xFF] >> 8) ^ (L4[(tmp[0] >> 8) & 0xFF] >> 16) ^ (L4[tmp[0] & 0xFF] >> 24);
		Block2[1] = L4[(tmp[1] >> 24) & 0xFF] ^ (L4[(tmp[1] >> 16) & 0xFF] >> 8) ^ (L4[(tmp[1] >> 8) & 0xFF] >> 16) ^ (L4[tmp[1] & 0xFF] >> 24);
		Block2[2] = L4[(tmp[2] >> 24) & 0xFF] ^ (L4[(tmp[2] >> 16) & 0xFF] >> 8) ^ (L4[(tmp[2] >> 8) & 0xFF] >> 16) ^ (L4[tmp[2] & 0xFF] >> 24);
		Block2[3] = L4[(tmp[3] >> 24) & 0xFF] ^ (L4[(tmp[3] >> 16) & 0xFF] >> 8) ^ (L4[(tmp[3] >> 8) & 0xFF] >> 16) ^ (L4[tmp[3] & 0xFF] >> 24);
		//L2
		tmp[0] = Block2[1] ^ Block2[2] ^ Block2[3];
		tmp[1] = Block2[0] ^ Block2[2] ^ Block2[3];
		tmp[2] = Block2[0] ^ Block2[1] ^ Block2[3];
		tmp[3] = Block2[0] ^ Block2[1] ^ Block2[2];

		//L1S
		Block2[0] = L0[(tmp[0] >> 24) & 0xFF] ^ L1[(tmp[0] >> 16) & 0xFF] ^ L2[(tmp[0] >> 8) & 0xFF] ^ L3[tmp[0] & 0xFF];
		Block2[1] = L0[(tmp[1] >> 16) & 0xFF] ^ L1[(tmp[1] >> 8) & 0xFF] ^ L2[tmp[1] & 0xFF] ^ L3[(tmp[1] >> 24) & 0xFF];
		Block2[2] = L0[(tmp[2] >> 8) & 0xFF] ^ L1[tmp[2] & 0xFF] ^ L2[(tmp[2] >> 24) & 0xFF] ^ L3[(tmp[2] >> 16) & 0xFF];
		Block2[3] = L0[tmp[3] & 0xFF] ^ L1[(tmp[3] >> 24) & 0xFF] ^ L2[(tmp[3] >> 16) & 0xFF] ^ L3[(tmp[3] >> 8) & 0xFF];
		//S2
		tmp[0] = L4[(Block2[0] >> 24) & 0xFF] ^ (L4[(Block2[0] >> 16) & 0xFF] >> 8) ^ (L4[(Block2[0] >> 8) & 0xFF] >> 16) ^ (L4[Block2[0] & 0xFF] >> 24);
		tmp[1] = L4[(Block2[1] >> 24) & 0xFF] ^ (L4[(Block2[1] >> 16) & 0xFF] >> 8) ^ (L4[(Block2[1] >> 8) & 0xFF] >> 16) ^ (L4[Block2[1] & 0xFF] >> 24);
		tmp[2] = L4[(Block2[2] >> 24) & 0xFF] ^ (L4[(Block2[2] >> 16) & 0xFF] >> 8) ^ (L4[(Block2[2] >> 8) & 0xFF] >> 16) ^ (L4[Block2[2] & 0xFF] >> 24);
		tmp[3] = L4[(Block2[3] >> 24) & 0xFF] ^ (L4[(Block2[3] >> 16) & 0xFF] >> 8) ^ (L4[(Block2[3] >> 8) & 0xFF] >> 16) ^ (L4[Block2[3] & 0xFF] >> 24);
		//L2
		Block2[0] = tmp[1] ^ tmp[2] ^ tmp[3];
		Block2[1] = tmp[0] ^ tmp[2] ^ tmp[3];
		Block2[2] = tmp[0] ^ tmp[1] ^ tmp[3];
		Block2[3] = tmp[0] ^ tmp[1] ^ tmp[2];


		tmp[0] = Block2[0];
		tmp[1] = Block2[1];
		tmp[2] = Block2[2];
		tmp[3] = Block2[3];
		//Tinh 2 nhanh theo luoc do V

		rKey[4 * (2 * i + 1) + 4] = Block2[0] = tmp[0] ^ Block1[0];
		rKey[4 * (2 * i + 1) + 5] = Block2[1] = tmp[1] ^ Block1[1];
		rKey[4 * (2 * i + 1) + 6] = Block2[2] = tmp[2] ^ Block1[2];
		rKey[4 * (2 * i + 1) + 7] = Block2[3] = tmp[3] ^ Block1[3];
		//
		rKey[4 * (2 * i + 1)] = Block1[0] = tmp[0];
		rKey[4 * (2 * i + 1) + 1] = Block1[1] = tmp[1];
		rKey[4 * (2 * i + 1) + 2] = Block1[2] = tmp[2];
		rKey[4 * (2 * i + 1) + 3] = Block1[3] = tmp[3];
		
	}
	return 1;
}
//u32 InvKey128(u32 in)
//{
//	u32 tmp = L4[(in >> 24) & 0xFF] ^ (L4[(in >> 16) & 0xFF] >> 8) ^ (L4[(in >> 8) & 0xFF] >> 16) ^ (L4[in & 0xFF] >> 24);  //Qua tang Shop
//	return iL0[(tmp >> 24) & 0xFF] ^ iL1[(tmp >> 16) & 0xFF] ^ iL2[(tmp >> 8) & 0xFF] ^ iL3[tmp & 0xFF];
//}

u32 InvKey128(u32 in)
{
	u32 tmp = L4[(in >> 24) & 0xFF] ^ (L4[(in >> 16) & 0xFF] >> 8) ^ (L4[(in >> 8) & 0xFF] >> 16) ^ (L4[in & 0xFF] >> 24);  //Qua tang Shop
	return iL0[(tmp >> 24) & 0xFF] ^ iL1[(tmp >> 16) & 0xFF] ^ iL2[(tmp >> 8) & 0xFF] ^ iL3[tmp & 0xFF];
}

int InvKeyExpansion128(
	int keyLen,							//Do dai khoa theo bit
	const unsigned char* MasterKey,	//Khoa chinh
	unsigned int* irKey)				//Khoa vong cho giai ma
{
	if (!keyLen || !MasterKey) return 0;
	int i;
	int round = Round128;
	KeyExpansion128(keyLen, MasterKey, irKey);
	if (keyLen == KeyLen192)  round = Round192;
	if (keyLen == KeyLen256)  round = Round256;
	unsigned int temp = 0;
	for (i = 1; i < 2 * round; i = i + 2) {
		irKey[4 * i] = InvKey128(irKey[4 * i]);
		irKey[4 * i + 1] = InvKey128(irKey[4 * i + 1]);
		irKey[4 * i + 2] = InvKey128(irKey[4 * i + 2]);
		irKey[4 * i + 3] = InvKey128(irKey[4 * i + 3]);
	}
	return 1;
}


int EncryptOneBlock128(
	int keyLen,				//Do dai khoa 128, 192, 256 bit
	unsigned int* rKey,		//Khoa vong
	unsigned char* in,		//Ban ro
	unsigned char* out)		//Ban ma
{
	u32 s0, s1, s2, s3, t0, t1, t2, t3;
	if (!in || !out || !rKey) return 0;

	t0 = GETU32(in) ^ rKey[0];
	t1 = GETU32(in + 4) ^ rKey[1];
	t2 = GETU32(in + 8) ^ rKey[2];
	t3 = GETU32(in + 12) ^ rKey[3];

	//r1
	//L1S --
	s0 = L0[(t0 >> 24) & 0xFF] ^ L1[(t0 >> 16) & 0xFF] ^ L2[(t0 >>  8) & 0xFF] ^ L3[ t0        & 0xFF] ^ rKey[4];
	s1 = L0[(t1 >> 16) & 0xFF] ^ L1[(t1 >>  8) & 0xFF] ^ L2[ t1        & 0xFF] ^ L3[(t1 >> 24) & 0xFF] ^ rKey[5];
	s2 = L0[(t2 >>  8) & 0xFF] ^ L1[(t2)       & 0xFF] ^ L2[(t2 >> 24) & 0xFF] ^ L3[(t2 >> 16) & 0xFF] ^ rKey[6];
	s3 = L0[ t3        & 0xFF] ^ L1[(t3 >> 24) & 0xFF] ^ L2[(t3 >> 16) & 0xFF] ^ L3[(t3 >>  8) & 0xFF] ^ rKey[7];

	//S
	t0 = L4[(s0 >> 24) & 0xFF] ^ (L4[(s0 >> 16) & 0xFF] >> 8) ^ (L4[(s0 >> 8) & 0xFF] >> 16) ^ (L4[s0 & 0xFF] >> 24);
	t1 = L4[(s1 >> 24) & 0xFF] ^ (L4[(s1 >> 16) & 0xFF] >> 8) ^ (L4[(s1 >> 8) & 0xFF] >> 16) ^ (L4[s1 & 0xFF] >> 24);
	t2 = L4[(s2 >> 24) & 0xFF] ^ (L4[(s2 >> 16) & 0xFF] >> 8) ^ (L4[(s2 >> 8) & 0xFF] >> 16) ^ (L4[s2 & 0xFF] >> 24);
	t3 = L4[(s3 >> 24) & 0xFF] ^ (L4[(s3 >> 16) & 0xFF] >> 8) ^ (L4[(s3 >> 8) & 0xFF] >> 16) ^ (L4[s3 & 0xFF] >> 24);
	//L2
	s0 = t1 ^ t2 ^ t3 ^ rKey[8];
	s1 = t0 ^ t2 ^ t3 ^ rKey[9];
	s2 = t0 ^ t1 ^ t3 ^ rKey[10];
	s3 = t0 ^ t1 ^ t2 ^ rKey[11];
	//r2
	//L1S
	t0 = L0[(s0 >> 24) & 0xFF] ^ L1[(s0 >> 16) & 0xFF] ^ L2[(s0 >> 8) & 0xFF] ^ L3[s0 & 0xFF] ^ rKey[12];
	t1 = L0[(s1 >> 16) & 0xFF] ^ L1[(s1 >> 8) & 0xFF] ^ L2[s1 & 0xFF] ^ L3[(s1 >> 24) & 0xFF] ^ rKey[13];
	t2 = L0[(s2 >> 8) & 0xFF] ^ L1[(s2) & 0xFF] ^ L2[(s2 >> 24) & 0xFF] ^ L3[(s2 >> 16) & 0xFF] ^ rKey[14];
	t3 = L0[s3 & 0xFF] ^ L1[(s3 >> 24) & 0xFF] ^ L2[(s3 >> 16) & 0xFF] ^ L3[(s3 >> 8) & 0xFF] ^ rKey[15];
	//S
	s0 = L4[(t0 >> 24) & 0xFF] ^ (L4[(t0 >> 16) & 0xFF] >> 8) ^ (L4[(t0 >> 8) & 0xFF] >> 16) ^ (L4[t0 & 0xFF] >> 24);
	s1 = L4[(t1 >> 24) & 0xFF] ^ (L4[(t1 >> 16) & 0xFF] >> 8) ^ (L4[(t1 >> 8) & 0xFF] >> 16) ^ (L4[t1 & 0xFF] >> 24);
	s2 = L4[(t2 >> 24) & 0xFF] ^ (L4[(t2 >> 16) & 0xFF] >> 8) ^ (L4[(t2 >> 8) & 0xFF] >> 16) ^ (L4[t2 & 0xFF] >> 24);
	s3 = L4[(t3 >> 24) & 0xFF] ^ (L4[(t3 >> 16) & 0xFF] >> 8) ^ (L4[(t3 >> 8) & 0xFF] >> 16) ^ (L4[t3 & 0xFF] >> 24);
	//L2
	t0 = s1 ^ s2 ^ s3 ^ rKey[16];
	t1 = s0 ^ s2 ^ s3 ^ rKey[17];
	t2 = s0 ^ s1 ^ s3 ^ rKey[18];
	t3 = s0 ^ s1 ^ s2 ^ rKey[19];

	//r3
	//L1S --
	s0 = L0[(t0 >> 24) & 0xFF] ^ L1[(t0 >> 16) & 0xFF] ^ L2[(t0 >> 8) & 0xFF] ^ L3[t0 & 0xFF] ^ rKey[20];
	s1 = L0[(t1 >> 16) & 0xFF] ^ L1[(t1 >> 8) & 0xFF] ^ L2[t1 & 0xFF] ^ L3[(t1 >> 24) & 0xFF] ^ rKey[21];
	s2 = L0[(t2 >> 8) & 0xFF] ^ L1[(t2) & 0xFF] ^ L2[(t2 >> 24) & 0xFF] ^ L3[(t2 >> 16) & 0xFF] ^ rKey[22];
	s3 = L0[t3 & 0xFF] ^ L1[(t3 >> 24) & 0xFF] ^ L2[(t3 >> 16) & 0xFF] ^ L3[(t3 >> 8) & 0xFF] ^ rKey[23];
	//S
	t0 = L4[(s0 >> 24) & 0xFF] ^ (L4[(s0 >> 16) & 0xFF] >> 8) ^ (L4[(s0 >> 8) & 0xFF] >> 16) ^ (L4[s0 & 0xFF] >> 24);
	t1 = L4[(s1 >> 24) & 0xFF] ^ (L4[(s1 >> 16) & 0xFF] >> 8) ^ (L4[(s1 >> 8) & 0xFF] >> 16) ^ (L4[s1 & 0xFF] >> 24);
	t2 = L4[(s2 >> 24) & 0xFF] ^ (L4[(s2 >> 16) & 0xFF] >> 8) ^ (L4[(s2 >> 8) & 0xFF] >> 16) ^ (L4[s2 & 0xFF] >> 24);
	t3 = L4[(s3 >> 24) & 0xFF] ^ (L4[(s3 >> 16) & 0xFF] >> 8) ^ (L4[(s3 >> 8) & 0xFF] >> 16) ^ (L4[s3 & 0xFF] >> 24);

	//L2
	s0 = t1 ^ t2 ^ t3 ^ rKey[24];
	s1 = t0 ^ t2 ^ t3 ^ rKey[25];
	s2 = t0 ^ t1 ^ t3 ^ rKey[26];
	s3 = t0 ^ t1 ^ t2 ^ rKey[27];

	//r4
	//L1S
	t0 = L0[(s0 >> 24) & 0xFF] ^ L1[(s0 >> 16) & 0xFF] ^ L2[(s0 >> 8) & 0xFF] ^ L3[s0 & 0xFF] ^ rKey[28];
	t1 = L0[(s1 >> 16) & 0xFF] ^ L1[(s1 >> 8) & 0xFF] ^ L2[s1 & 0xFF] ^ L3[(s1 >> 24) & 0xFF] ^ rKey[29];
	t2 = L0[(s2 >> 8) & 0xFF] ^ L1[(s2) & 0xFF] ^ L2[(s2 >> 24) & 0xFF] ^ L3[(s2 >> 16) & 0xFF] ^ rKey[30];
	t3 = L0[s3 & 0xFF] ^ L1[(s3 >> 24) & 0xFF] ^ L2[(s3 >> 16) & 0xFF] ^ L3[(s3 >> 8) & 0xFF] ^ rKey[31];
	//S
	s0 = L4[(t0 >> 24) & 0xFF] ^ (L4[(t0 >> 16) & 0xFF] >> 8) ^ (L4[(t0 >> 8) & 0xFF] >> 16) ^ (L4[t0 & 0xFF] >> 24);
	s1 = L4[(t1 >> 24) & 0xFF] ^ (L4[(t1 >> 16) & 0xFF] >> 8) ^ (L4[(t1 >> 8) & 0xFF] >> 16) ^ (L4[t1 & 0xFF] >> 24);
	s2 = L4[(t2 >> 24) & 0xFF] ^ (L4[(t2 >> 16) & 0xFF] >> 8) ^ (L4[(t2 >> 8) & 0xFF] >> 16) ^ (L4[t2 & 0xFF] >> 24);
	s3 = L4[(t3 >> 24) & 0xFF] ^ (L4[(t3 >> 16) & 0xFF] >> 8) ^ (L4[(t3 >> 8) & 0xFF] >> 16) ^ (L4[t3 & 0xFF] >> 24);
	//L2
	t0 = s1 ^ s2 ^ s3 ^ rKey[32];
	t1 = s0 ^ s2 ^ s3 ^ rKey[33];
	t2 = s0 ^ s1 ^ s3 ^ rKey[34];
	t3 = s0 ^ s1 ^ s2 ^ rKey[35];

	//r5
	//L1S --
	s0 = L0[(t0 >> 24) & 0xFF] ^ L1[(t0 >> 16) & 0xFF] ^ L2[(t0 >> 8) & 0xFF] ^ L3[t0 & 0xFF] ^ rKey[36];
	s1 = L0[(t1 >> 16) & 0xFF] ^ L1[(t1 >> 8) & 0xFF] ^ L2[t1 & 0xFF] ^ L3[(t1 >> 24) & 0xFF] ^ rKey[37];
	s2 = L0[(t2 >> 8) & 0xFF] ^ L1[(t2) & 0xFF] ^ L2[(t2 >> 24) & 0xFF] ^ L3[(t2 >> 16) & 0xFF] ^ rKey[38];
	s3 = L0[t3 & 0xFF] ^ L1[(t3 >> 24) & 0xFF] ^ L2[(t3 >> 16) & 0xFF] ^ L3[(t3 >> 8) & 0xFF] ^ rKey[39];
	//S
	t0 = L4[(s0 >> 24) & 0xFF] ^ (L4[(s0 >> 16) & 0xFF] >> 8) ^ (L4[(s0 >> 8) & 0xFF] >> 16) ^ (L4[s0 & 0xFF] >> 24);
	t1 = L4[(s1 >> 24) & 0xFF] ^ (L4[(s1 >> 16) & 0xFF] >> 8) ^ (L4[(s1 >> 8) & 0xFF] >> 16) ^ (L4[s1 & 0xFF] >> 24);
	t2 = L4[(s2 >> 24) & 0xFF] ^ (L4[(s2 >> 16) & 0xFF] >> 8) ^ (L4[(s2 >> 8) & 0xFF] >> 16) ^ (L4[s2 & 0xFF] >> 24);
	t3 = L4[(s3 >> 24) & 0xFF] ^ (L4[(s3 >> 16) & 0xFF] >> 8) ^ (L4[(s3 >> 8) & 0xFF] >> 16) ^ (L4[s3 & 0xFF] >> 24);
	//L2
	s0 = t1 ^ t2 ^ t3 ^ rKey[40];
	s1 = t0 ^ t2 ^ t3 ^ rKey[41];
	s2 = t0 ^ t1 ^ t3 ^ rKey[42];
	s3 = t0 ^ t1 ^ t2 ^ rKey[43];

	//r6
	//L1S
	t0 = L0[(s0 >> 24) & 0xFF] ^ L1[(s0 >> 16) & 0xFF] ^ L2[(s0 >> 8) & 0xFF] ^ L3[s0 & 0xFF] ^ rKey[44];
	t1 = L0[(s1 >> 16) & 0xFF] ^ L1[(s1 >> 8) & 0xFF] ^ L2[s1 & 0xFF] ^ L3[(s1 >> 24) & 0xFF] ^ rKey[45];
	t2 = L0[(s2 >> 8) & 0xFF] ^ L1[(s2) & 0xFF] ^ L2[(s2 >> 24) & 0xFF] ^ L3[(s2 >> 16) & 0xFF] ^ rKey[46];
	t3 = L0[s3 & 0xFF] ^ L1[(s3 >> 24) & 0xFF] ^ L2[(s3 >> 16) & 0xFF] ^ L3[(s3 >> 8) & 0xFF] ^ rKey[47];
	//S
	s0 = L4[(t0 >> 24) & 0xFF] ^ (L4[(t0 >> 16) & 0xFF] >> 8) ^ (L4[(t0 >> 8) & 0xFF] >> 16) ^ (L4[t0 & 0xFF] >> 24);
	s1 = L4[(t1 >> 24) & 0xFF] ^ (L4[(t1 >> 16) & 0xFF] >> 8) ^ (L4[(t1 >> 8) & 0xFF] >> 16) ^ (L4[t1 & 0xFF] >> 24);
	s2 = L4[(t2 >> 24) & 0xFF] ^ (L4[(t2 >> 16) & 0xFF] >> 8) ^ (L4[(t2 >> 8) & 0xFF] >> 16) ^ (L4[t2 & 0xFF] >> 24);
	s3 = L4[(t3 >> 24) & 0xFF] ^ (L4[(t3 >> 16) & 0xFF] >> 8) ^ (L4[(t3 >> 8) & 0xFF] >> 16) ^ (L4[t3 & 0xFF] >> 24);
	//L2
	t0 = s1 ^ s2 ^ s3 ^ rKey[48];
	t1 = s0 ^ s2 ^ s3 ^ rKey[49];
	t2 = s0 ^ s1 ^ s3 ^ rKey[50];
	t3 = s0 ^ s1 ^ s2 ^ rKey[51];

	//r7
	//L1S --
	s0 = L0[(t0 >> 24) & 0xFF] ^ L1[(t0 >> 16) & 0xFF] ^ L2[(t0 >> 8) & 0xFF] ^ L3[t0 & 0xFF] ^ rKey[52];
	s1 = L0[(t1 >> 16) & 0xFF] ^ L1[(t1 >> 8) & 0xFF] ^ L2[t1 & 0xFF] ^ L3[(t1 >> 24) & 0xFF] ^ rKey[53];
	s2 = L0[(t2 >> 8) & 0xFF] ^ L1[(t2) & 0xFF] ^ L2[(t2 >> 24) & 0xFF] ^ L3[(t2 >> 16) & 0xFF] ^ rKey[54];
	s3 = L0[t3 & 0xFF] ^ L1[(t3 >> 24) & 0xFF] ^ L2[(t3 >> 16) & 0xFF] ^ L3[(t3 >> 8) & 0xFF] ^ rKey[55];
	//S
	t0 = L4[(s0 >> 24) & 0xFF] ^ (L4[(s0 >> 16) & 0xFF] >> 8) ^ (L4[(s0 >> 8) & 0xFF] >> 16) ^ (L4[s0 & 0xFF] >> 24);
	t1 = L4[(s1 >> 24) & 0xFF] ^ (L4[(s1 >> 16) & 0xFF] >> 8) ^ (L4[(s1 >> 8) & 0xFF] >> 16) ^ (L4[s1 & 0xFF] >> 24);
	t2 = L4[(s2 >> 24) & 0xFF] ^ (L4[(s2 >> 16) & 0xFF] >> 8) ^ (L4[(s2 >> 8) & 0xFF] >> 16) ^ (L4[s2 & 0xFF] >> 24);
	t3 = L4[(s3 >> 24) & 0xFF] ^ (L4[(s3 >> 16) & 0xFF] >> 8) ^ (L4[(s3 >> 8) & 0xFF] >> 16) ^ (L4[s3 & 0xFF] >> 24);
	//L2
	s0 = t1 ^ t2 ^ t3 ^ rKey[56];
	s1 = t0 ^ t2 ^ t3 ^ rKey[57];
	s2 = t0 ^ t1 ^ t3 ^ rKey[58];
	s3 = t0 ^ t1 ^ t2 ^ rKey[59];

	if (keyLen == KeyLen128) {
		PUTU32(out, s0);
		PUTU32(out + 4, s1);
		PUTU32(out + 8, s2);
		PUTU32(out + 12, s3);
	}
	if (keyLen >= KeyLen192) {
		//r8
		//L1S
		t0 = L0[(s0 >> 24) & 0xFF] ^ L1[(s0 >> 16) & 0xFF] ^ L2[(s0 >> 8) & 0xFF] ^ L3[s0 & 0xFF] ^ rKey[60];
		t1 = L0[(s1 >> 16) & 0xFF] ^ L1[(s1 >> 8) & 0xFF] ^ L2[s1 & 0xFF] ^ L3[(s1 >> 24) & 0xFF] ^ rKey[61];
		t2 = L0[(s2 >> 8) & 0xFF] ^ L1[(s2) & 0xFF] ^ L2[(s2 >> 24) & 0xFF] ^ L3[(s2 >> 16) & 0xFF] ^ rKey[62];
		t3 = L0[s3 & 0xFF] ^ L1[(s3 >> 24) & 0xFF] ^ L2[(s3 >> 16) & 0xFF] ^ L3[(s3 >> 8) & 0xFF] ^ rKey[63];
		//S
		s0 = L4[(t0 >> 24) & 0xFF] ^ (L4[(t0 >> 16) & 0xFF] >> 8) ^ (L4[(t0 >> 8) & 0xFF] >> 16) ^ (L4[t0 & 0xFF] >> 24);
		s1 = L4[(t1 >> 24) & 0xFF] ^ (L4[(t1 >> 16) & 0xFF] >> 8) ^ (L4[(t1 >> 8) & 0xFF] >> 16) ^ (L4[t1 & 0xFF] >> 24);
		s2 = L4[(t2 >> 24) & 0xFF] ^ (L4[(t2 >> 16) & 0xFF] >> 8) ^ (L4[(t2 >> 8) & 0xFF] >> 16) ^ (L4[t2 & 0xFF] >> 24);
		s3 = L4[(t3 >> 24) & 0xFF] ^ (L4[(t3 >> 16) & 0xFF] >> 8) ^ (L4[(t3 >> 8) & 0xFF] >> 16) ^ (L4[t3 & 0xFF] >> 24);
		//L2
		t0 = s1 ^ s2 ^ s3 ^ rKey[64];
		t1 = s0 ^ s2 ^ s3 ^ rKey[65];
		t2 = s0 ^ s1 ^ s3 ^ rKey[66];
		t3 = s0 ^ s1 ^ s2 ^ rKey[67];

		PUTU32(out, t0);
		PUTU32(out + 4, t1);
		PUTU32(out + 8, t2);
		PUTU32(out + 12, t3);
		if (keyLen == KeyLen256) {

			//r9
			//L1S
			s0 = L0[(t0 >> 24) & 0xFF] ^ L1[(t0 >> 16) & 0xFF] ^ L2[(t0 >> 8) & 0xFF] ^ L3[t0 & 0xFF] ^ rKey[68];
			s1 = L0[(t1 >> 16) & 0xFF] ^ L1[(t1 >> 8) & 0xFF] ^ L2[t1 & 0xFF] ^ L3[(t1 >> 24) & 0xFF] ^ rKey[69];
			s2 = L0[(t2 >> 8) & 0xFF] ^ L1[(t2) & 0xFF] ^ L2[(t2 >> 24) & 0xFF] ^ L3[(t2 >> 16) & 0xFF] ^ rKey[70];
			s3 = L0[t3 & 0xFF] ^ L1[(t3 >> 24) & 0xFF] ^ L2[(t3 >> 16) & 0xFF] ^ L3[(t3 >> 8) & 0xFF] ^ rKey[71];
			//S
			t0 = L4[(s0 >> 24) & 0xFF] ^ (L4[(s0 >> 16) & 0xFF] >> 8) ^ (L4[(s0 >> 8) & 0xFF] >> 16) ^ (L4[s0 & 0xFF] >> 24);
			t1 = L4[(s1 >> 24) & 0xFF] ^ (L4[(s1 >> 16) & 0xFF] >> 8) ^ (L4[(s1 >> 8) & 0xFF] >> 16) ^ (L4[s1 & 0xFF] >> 24);
			t2 = L4[(s2 >> 24) & 0xFF] ^ (L4[(s2 >> 16) & 0xFF] >> 8) ^ (L4[(s2 >> 8) & 0xFF] >> 16) ^ (L4[s2 & 0xFF] >> 24);
			t3 = L4[(s3 >> 24) & 0xFF] ^ (L4[(s3 >> 16) & 0xFF] >> 8) ^ (L4[(s3 >> 8) & 0xFF] >> 16) ^ (L4[s3 & 0xFF] >> 24);
			//L2
			s0 = t1 ^ t2 ^ t3 ^ rKey[72];
			s1 = t0 ^ t2 ^ t3 ^ rKey[73];
			s2 = t0 ^ t1 ^ t3 ^ rKey[74];
			s3 = t0 ^ t1 ^ t2 ^ rKey[75];

			PUTU32(out, s0);
			PUTU32(out + 4, s1);
			PUTU32(out + 8, s2);
			PUTU32(out + 12, s3);
		}
	}
	return 1;
}

void printState128_(u32 A0, u32 A1, u32 A2, u32 A3) {
	printf("%08X %08X %08X %08X\n", A0, A1, A2, A3);
}


int DecryptOneBlock128(
	int keyLen,				//Do dai khoa 128, 192, 256 bit
	unsigned int* rKey,	//Khoa vong
	unsigned char* in,		//Ban ma
	unsigned char* out)	//Ban ro sau giai ma
{
	u32 s0, s1, s2, s3, t0 = 0, t1 = 0, t2 = 0, t3 = 0;
	if (!keyLen || !in || !out || !rKey) return 0;

	if (keyLen == KeyLen256) {
		t0 = GETU32(in) ^ rKey[72];
		t1 = GETU32(in + 4) ^ rKey[73];
		t2 = GETU32(in + 8) ^ rKey[74];
		t3 = GETU32(in + 12) ^ rKey[75];
		//r9
		//L2
		s0 = t1 ^ t2 ^ t3;
		s1 = t0 ^ t2 ^ t3;
		s2 = t0 ^ t1 ^ t3;
		s3 = t0 ^ t1 ^ t2;
		//iL1S
		t0 = iL0[(s0 >> 24) & 0xFF] ^ iL1[(s0 >> 16) & 0xFF] ^ iL2[(s0 >> 8) & 0xFF] ^ iL3[s0 & 0xFF] ^ rKey[68];
		t1 = iL0[(s1 >> 24) & 0xFF] ^ iL1[(s1 >> 16) & 0xFF] ^ iL2[(s1 >> 8) & 0xFF] ^ iL3[s1 & 0xFF] ^ rKey[69];
		t2 = iL0[(s2 >> 24) & 0xFF] ^ iL1[(s2 >> 16) & 0xFF] ^ iL2[(s2 >> 8) & 0xFF] ^ iL3[s2 & 0xFF] ^ rKey[70];
		t3 = iL0[(s3 >> 24) & 0xFF] ^ iL1[(s3 >> 16) & 0xFF] ^ iL2[(s3 >> 8) & 0xFF] ^ iL3[s3 & 0xFF] ^ rKey[71];
		//S --
		s0 = iL4[(t0 >> 24) & 0xFF] ^ (iL4[(t0 >> 16) & 0xFF] >> 8) ^ (iL4[(t0 >>  8) & 0xFF] >> 16) ^ (iL4[(t0      ) & 0xFF] >> 24) ^ rKey[64];
		s1 = iL4[(t1      ) & 0xFF] ^ (iL4[(t1 >> 24) & 0xFF] >> 8) ^ (iL4[(t1 >> 16) & 0xFF] >> 16) ^ (iL4[(t1 >>  8) & 0xFF] >> 24) ^ rKey[65];
		s2 = iL4[(t2 >>  8) & 0xFF] ^ (iL4[(t2      ) & 0xFF] >> 8) ^ (iL4[(t2 >> 24) & 0xFF] >> 16) ^ (iL4[(t2 >> 16) & 0xFF] >> 24) ^ rKey[66];
		s3 = iL4[(t3 >> 16) & 0xFF] ^ (iL4[(t3 >>  8) & 0xFF] >> 8) ^ (iL4[(t3      ) & 0xFF] >> 16) ^ (iL4[(t3 >> 24) & 0xFF] >> 24) ^ rKey[67];

		//r8
		//L2
		t0 = s1 ^ s2 ^ s3;
		t1 = s0 ^ s2 ^ s3;
		t2 = s0 ^ s1 ^ s3;
		t3 = s0 ^ s1 ^ s2;
		//iL1S
		s0 = iL0[(t0 >> 24) & 0xFF] ^ iL1[(t0 >> 16) & 0xFF] ^ iL2[(t0 >> 8) & 0xFF] ^ iL3[t0 & 0xFF] ^ rKey[60];
		s1 = iL0[(t1 >> 24) & 0xFF] ^ iL1[(t1 >> 16) & 0xFF] ^ iL2[(t1 >> 8) & 0xFF] ^ iL3[t1 & 0xFF] ^ rKey[61];
		s2 = iL0[(t2 >> 24) & 0xFF] ^ iL1[(t2 >> 16) & 0xFF] ^ iL2[(t2 >> 8) & 0xFF] ^ iL3[t2 & 0xFF] ^ rKey[62];
		s3 = iL0[(t3 >> 24) & 0xFF] ^ iL1[(t3 >> 16) & 0xFF] ^ iL2[(t3 >> 8) & 0xFF] ^ iL3[t3 & 0xFF] ^ rKey[63];
		//S ++
		t0 = iL4[(s0 >> 24) & 0xFF] ^ (iL4[(s0 >> 16) & 0xFF] >> 8) ^ (iL4[(s0 >> 8) & 0xFF] >> 16) ^ (iL4[(s0) & 0xFF] >> 24) ^ rKey[56];
		t1 = iL4[(s1) & 0xFF] ^ (iL4[(s1 >> 24) & 0xFF] >> 8) ^ (iL4[(s1 >> 16) & 0xFF] >> 16) ^ (iL4[(s1 >> 8) & 0xFF] >> 24) ^ rKey[57];
		t2 = iL4[(s2 >> 8) & 0xFF] ^ (iL4[(s2) & 0xFF] >> 8) ^ (iL4[(s2 >> 24) & 0xFF] >> 16) ^ (iL4[(s2 >> 16) & 0xFF] >> 24) ^ rKey[58];
		t3 = iL4[(s3 >> 16) & 0xFF] ^ (iL4[(s3 >> 8) & 0xFF] >> 8) ^ (iL4[(s3) & 0xFF] >> 16) ^ (iL4[(s3 >> 24) & 0xFF] >> 24) ^ rKey[59];

	}
	if (keyLen == KeyLen192) {
		s0 = GETU32(in) ^ rKey[64];
		s1 = GETU32(in + 4) ^ rKey[65];
		s2 = GETU32(in + 8) ^ rKey[66];
		s3 = GETU32(in + 12) ^ rKey[67];

		//r8
		//L2
		t0 = s1 ^ s2 ^ s3;
		t1 = s0 ^ s2 ^ s3;
		t2 = s0 ^ s1 ^ s3;
		t3 = s0 ^ s1 ^ s2;
		//iL1S
		s0 = iL0[(t0 >> 24) & 0xFF] ^ iL1[(t0 >> 16) & 0xFF] ^ iL2[(t0 >> 8) & 0xFF] ^ iL3[t0 & 0xFF] ^ rKey[60];
		s1 = iL0[(t1 >> 24) & 0xFF] ^ iL1[(t1 >> 16) & 0xFF] ^ iL2[(t1 >> 8) & 0xFF] ^ iL3[t1 & 0xFF] ^ rKey[61];
		s2 = iL0[(t2 >> 24) & 0xFF] ^ iL1[(t2 >> 16) & 0xFF] ^ iL2[(t2 >> 8) & 0xFF] ^ iL3[t2 & 0xFF] ^ rKey[62];
		s3 = iL0[(t3 >> 24) & 0xFF] ^ iL1[(t3 >> 16) & 0xFF] ^ iL2[(t3 >> 8) & 0xFF] ^ iL3[t3 & 0xFF] ^ rKey[63];
		//S ++
		t0 = iL4[(s0 >> 24) & 0xFF] ^ (iL4[(s0 >> 16) & 0xFF] >> 8) ^ (iL4[(s0 >> 8) & 0xFF] >> 16) ^ (iL4[(s0) & 0xFF] >> 24) ^ rKey[56];
		t1 = iL4[(s1) & 0xFF] ^ (iL4[(s1 >> 24) & 0xFF] >> 8) ^ (iL4[(s1 >> 16) & 0xFF] >> 16) ^ (iL4[(s1 >> 8) & 0xFF] >> 24) ^ rKey[57];
		t2 = iL4[(s2 >> 8) & 0xFF] ^ (iL4[(s2) & 0xFF] >> 8) ^ (iL4[(s2 >> 24) & 0xFF] >> 16) ^ (iL4[(s2 >> 16) & 0xFF] >> 24) ^ rKey[58];
		t3 = iL4[(s3 >> 16) & 0xFF] ^ (iL4[(s3 >> 8) & 0xFF] >> 8) ^ (iL4[(s3) & 0xFF] >> 16) ^ (iL4[(s3 >> 24) & 0xFF] >> 24) ^ rKey[59];

	}

	if (keyLen == KeyLen128) {
		t0 = GETU32(in) ^ rKey[56];
		t1 = GETU32(in + 4) ^ rKey[57];
		t2 = GETU32(in + 8) ^ rKey[58];
		t3 = GETU32(in + 12) ^ rKey[59];
	}

	//r7
	//L2
	s0 = t1 ^ t2 ^ t3;
	s1 = t0 ^ t2 ^ t3;
	s2 = t0 ^ t1 ^ t3;
	s3 = t0 ^ t1 ^ t2;
	//iL1S
	t0 = iL0[(s0 >> 24) & 0xFF] ^ iL1[(s0 >> 16) & 0xFF] ^ iL2[(s0 >> 8) & 0xFF] ^ iL3[s0 & 0xFF] ^ rKey[52];
	t1 = iL0[(s1 >> 24) & 0xFF] ^ iL1[(s1 >> 16) & 0xFF] ^ iL2[(s1 >> 8) & 0xFF] ^ iL3[s1 & 0xFF] ^ rKey[53];
	t2 = iL0[(s2 >> 24) & 0xFF] ^ iL1[(s2 >> 16) & 0xFF] ^ iL2[(s2 >> 8) & 0xFF] ^ iL3[s2 & 0xFF] ^ rKey[54];
	t3 = iL0[(s3 >> 24) & 0xFF] ^ iL1[(s3 >> 16) & 0xFF] ^ iL2[(s3 >> 8) & 0xFF] ^ iL3[s3 & 0xFF] ^ rKey[55];
	//S
	s0 = iL4[(t0 >> 24) & 0xFF] ^ (iL4[(t0 >> 16) & 0xFF] >> 8) ^ (iL4[(t0 >> 8) & 0xFF] >> 16) ^ (iL4[(t0) & 0xFF] >> 24) ^ rKey[48];
	s1 = iL4[(t1) & 0xFF] ^ (iL4[(t1 >> 24) & 0xFF] >> 8) ^ (iL4[(t1 >> 16) & 0xFF] >> 16) ^ (iL4[(t1 >> 8) & 0xFF] >> 24) ^ rKey[49];
	s2 = iL4[(t2 >> 8) & 0xFF] ^ (iL4[(t2) & 0xFF] >> 8) ^ (iL4[(t2 >> 24) & 0xFF] >> 16) ^ (iL4[(t2 >> 16) & 0xFF] >> 24) ^ rKey[50];
	s3 = iL4[(t3 >> 16) & 0xFF] ^ (iL4[(t3 >> 8) & 0xFF] >> 8) ^ (iL4[(t3) & 0xFF] >> 16) ^ (iL4[(t3 >> 24) & 0xFF] >> 24) ^ rKey[51];

	//r6
	//L2
	t0 = s1 ^ s2 ^ s3;
	t1 = s0 ^ s2 ^ s3;
	t2 = s0 ^ s1 ^ s3;
	t3 = s0 ^ s1 ^ s2;
	//iL1S
	s0 = iL0[(t0 >> 24) & 0xFF] ^ iL1[(t0 >> 16) & 0xFF] ^ iL2[(t0 >> 8) & 0xFF] ^ iL3[t0 & 0xFF] ^ rKey[44];
	s1 = iL0[(t1 >> 24) & 0xFF] ^ iL1[(t1 >> 16) & 0xFF] ^ iL2[(t1 >> 8) & 0xFF] ^ iL3[t1 & 0xFF] ^ rKey[45];
	s2 = iL0[(t2 >> 24) & 0xFF] ^ iL1[(t2 >> 16) & 0xFF] ^ iL2[(t2 >> 8) & 0xFF] ^ iL3[t2 & 0xFF] ^ rKey[46];
	s3 = iL0[(t3 >> 24) & 0xFF] ^ iL1[(t3 >> 16) & 0xFF] ^ iL2[(t3 >> 8) & 0xFF] ^ iL3[t3 & 0xFF] ^ rKey[47];
	//S
	t0 = iL4[(s0 >> 24) & 0xFF] ^ (iL4[(s0 >> 16) & 0xFF] >> 8) ^ (iL4[(s0 >> 8) & 0xFF] >> 16) ^ (iL4[(s0) & 0xFF] >> 24) ^ rKey[40];
	t1 = iL4[(s1) & 0xFF] ^ (iL4[(s1 >> 24) & 0xFF] >> 8) ^ (iL4[(s1 >> 16) & 0xFF] >> 16) ^ (iL4[(s1 >> 8) & 0xFF] >> 24) ^ rKey[41];
	t2 = iL4[(s2 >> 8) & 0xFF] ^ (iL4[(s2) & 0xFF] >> 8) ^ (iL4[(s2 >> 24) & 0xFF] >> 16) ^ (iL4[(s2 >> 16) & 0xFF] >> 24) ^ rKey[42];
	t3 = iL4[(s3 >> 16) & 0xFF] ^ (iL4[(s3 >> 8) & 0xFF] >> 8) ^ (iL4[(s3) & 0xFF] >> 16) ^ (iL4[(s3 >> 24) & 0xFF] >> 24) ^ rKey[43];

	//r5
	//L2
	s0 = t1 ^ t2 ^ t3;
	s1 = t0 ^ t2 ^ t3;
	s2 = t0 ^ t1 ^ t3;
	s3 = t0 ^ t1 ^ t2;
	//iL1S
	t0 = iL0[(s0 >> 24) & 0xFF] ^ iL1[(s0 >> 16) & 0xFF] ^ iL2[(s0 >> 8) & 0xFF] ^ iL3[s0 & 0xFF] ^ rKey[36];
	t1 = iL0[(s1 >> 24) & 0xFF] ^ iL1[(s1 >> 16) & 0xFF] ^ iL2[(s1 >> 8) & 0xFF] ^ iL3[s1 & 0xFF] ^ rKey[37];
	t2 = iL0[(s2 >> 24) & 0xFF] ^ iL1[(s2 >> 16) & 0xFF] ^ iL2[(s2 >> 8) & 0xFF] ^ iL3[s2 & 0xFF] ^ rKey[38];
	t3 = iL0[(s3 >> 24) & 0xFF] ^ iL1[(s3 >> 16) & 0xFF] ^ iL2[(s3 >> 8) & 0xFF] ^ iL3[s3 & 0xFF] ^ rKey[39];
	//S
	s0 = iL4[(t0 >> 24) & 0xFF] ^ (iL4[(t0 >> 16) & 0xFF] >> 8) ^ (iL4[(t0 >> 8) & 0xFF] >> 16) ^ (iL4[(t0) & 0xFF] >> 24) ^ rKey[32];
	s1 = iL4[(t1) & 0xFF] ^ (iL4[(t1 >> 24) & 0xFF] >> 8) ^ (iL4[(t1 >> 16) & 0xFF] >> 16) ^ (iL4[(t1 >> 8) & 0xFF] >> 24) ^ rKey[33];
	s2 = iL4[(t2 >> 8) & 0xFF] ^ (iL4[(t2) & 0xFF] >> 8) ^ (iL4[(t2 >> 24) & 0xFF] >> 16) ^ (iL4[(t2 >> 16) & 0xFF] >> 24) ^ rKey[34];
	s3 = iL4[(t3 >> 16) & 0xFF] ^ (iL4[(t3 >> 8) & 0xFF] >> 8) ^ (iL4[(t3) & 0xFF] >> 16) ^ (iL4[(t3 >> 24) & 0xFF] >> 24) ^ rKey[35];

	//r4
	//L2
	t0 = s1 ^ s2 ^ s3;
	t1 = s0 ^ s2 ^ s3;
	t2 = s0 ^ s1 ^ s3;
	t3 = s0 ^ s1 ^ s2;
	//iL1S
	s0 = iL0[(t0 >> 24) & 0xFF] ^ iL1[(t0 >> 16) & 0xFF] ^ iL2[(t0 >> 8) & 0xFF] ^ iL3[t0 & 0xFF] ^ rKey[28];
	s1 = iL0[(t1 >> 24) & 0xFF] ^ iL1[(t1 >> 16) & 0xFF] ^ iL2[(t1 >> 8) & 0xFF] ^ iL3[t1 & 0xFF] ^ rKey[29];
	s2 = iL0[(t2 >> 24) & 0xFF] ^ iL1[(t2 >> 16) & 0xFF] ^ iL2[(t2 >> 8) & 0xFF] ^ iL3[t2 & 0xFF] ^ rKey[30];
	s3 = iL0[(t3 >> 24) & 0xFF] ^ iL1[(t3 >> 16) & 0xFF] ^ iL2[(t3 >> 8) & 0xFF] ^ iL3[t3 & 0xFF] ^ rKey[31];
	//S
	t0 = iL4[(s0 >> 24) & 0xFF] ^ (iL4[(s0 >> 16) & 0xFF] >> 8) ^ (iL4[(s0 >> 8) & 0xFF] >> 16) ^ (iL4[(s0) & 0xFF] >> 24) ^ rKey[24];
	t1 = iL4[(s1) & 0xFF] ^ (iL4[(s1 >> 24) & 0xFF] >> 8) ^ (iL4[(s1 >> 16) & 0xFF] >> 16) ^ (iL4[(s1 >> 8) & 0xFF] >> 24) ^ rKey[25];
	t2 = iL4[(s2 >> 8) & 0xFF] ^ (iL4[(s2) & 0xFF] >> 8) ^ (iL4[(s2 >> 24) & 0xFF] >> 16) ^ (iL4[(s2 >> 16) & 0xFF] >> 24) ^ rKey[26];
	t3 = iL4[(s3 >> 16) & 0xFF] ^ (iL4[(s3 >> 8) & 0xFF] >> 8) ^ (iL4[(s3) & 0xFF] >> 16) ^ (iL4[(s3 >> 24) & 0xFF] >> 24) ^ rKey[27];

	//r3
	//L2
	s0 = t1 ^ t2 ^ t3;
	s1 = t0 ^ t2 ^ t3;
	s2 = t0 ^ t1 ^ t3;
	s3 = t0 ^ t1 ^ t2;
	//iL1S
	t0 = iL0[(s0 >> 24) & 0xFF] ^ iL1[(s0 >> 16) & 0xFF] ^ iL2[(s0 >> 8) & 0xFF] ^ iL3[s0 & 0xFF] ^ rKey[20];
	t1 = iL0[(s1 >> 24) & 0xFF] ^ iL1[(s1 >> 16) & 0xFF] ^ iL2[(s1 >> 8) & 0xFF] ^ iL3[s1 & 0xFF] ^ rKey[21];
	t2 = iL0[(s2 >> 24) & 0xFF] ^ iL1[(s2 >> 16) & 0xFF] ^ iL2[(s2 >> 8) & 0xFF] ^ iL3[s2 & 0xFF] ^ rKey[22];
	t3 = iL0[(s3 >> 24) & 0xFF] ^ iL1[(s3 >> 16) & 0xFF] ^ iL2[(s3 >> 8) & 0xFF] ^ iL3[s3 & 0xFF] ^ rKey[23];
	//S
	s0 = iL4[(t0 >> 24) & 0xFF] ^ (iL4[(t0 >> 16) & 0xFF] >> 8) ^ (iL4[(t0 >> 8) & 0xFF] >> 16) ^ (iL4[(t0) & 0xFF] >> 24) ^ rKey[16];
	s1 = iL4[(t1) & 0xFF] ^ (iL4[(t1 >> 24) & 0xFF] >> 8) ^ (iL4[(t1 >> 16) & 0xFF] >> 16) ^ (iL4[(t1 >> 8) & 0xFF] >> 24) ^ rKey[17];
	s2 = iL4[(t2 >> 8) & 0xFF] ^ (iL4[(t2) & 0xFF] >> 8) ^ (iL4[(t2 >> 24) & 0xFF] >> 16) ^ (iL4[(t2 >> 16) & 0xFF] >> 24) ^ rKey[18];
	s3 = iL4[(t3 >> 16) & 0xFF] ^ (iL4[(t3 >> 8) & 0xFF] >> 8) ^ (iL4[(t3) & 0xFF] >> 16) ^ (iL4[(t3 >> 24) & 0xFF] >> 24) ^ rKey[19];

	//r2
	//L2
	t0 = s1 ^ s2 ^ s3;
	t1 = s0 ^ s2 ^ s3;
	t2 = s0 ^ s1 ^ s3;
	t3 = s0 ^ s1 ^ s2;
	//iL1S
	s0 = iL0[(t0 >> 24) & 0xFF] ^ iL1[(t0 >> 16) & 0xFF] ^ iL2[(t0 >> 8) & 0xFF] ^ iL3[t0 & 0xFF] ^ rKey[12];
	s1 = iL0[(t1 >> 24) & 0xFF] ^ iL1[(t1 >> 16) & 0xFF] ^ iL2[(t1 >> 8) & 0xFF] ^ iL3[t1 & 0xFF] ^ rKey[13];
	s2 = iL0[(t2 >> 24) & 0xFF] ^ iL1[(t2 >> 16) & 0xFF] ^ iL2[(t2 >> 8) & 0xFF] ^ iL3[t2 & 0xFF] ^ rKey[14];
	s3 = iL0[(t3 >> 24) & 0xFF] ^ iL1[(t3 >> 16) & 0xFF] ^ iL2[(t3 >> 8) & 0xFF] ^ iL3[t3 & 0xFF] ^ rKey[15];
	//S
	t0 = iL4[(s0 >> 24) & 0xFF] ^ (iL4[(s0 >> 16) & 0xFF] >> 8) ^ (iL4[(s0 >> 8) & 0xFF] >> 16) ^ (iL4[(s0) & 0xFF] >> 24) ^ rKey[8];
	t1 = iL4[(s1) & 0xFF] ^ (iL4[(s1 >> 24) & 0xFF] >> 8) ^ (iL4[(s1 >> 16) & 0xFF] >> 16) ^ (iL4[(s1 >> 8) & 0xFF] >> 24) ^ rKey[9];
	t2 = iL4[(s2 >> 8) & 0xFF] ^ (iL4[(s2) & 0xFF] >> 8) ^ (iL4[(s2 >> 24) & 0xFF] >> 16) ^ (iL4[(s2 >> 16) & 0xFF] >> 24) ^ rKey[10];
	t3 = iL4[(s3 >> 16) & 0xFF] ^ (iL4[(s3 >> 8) & 0xFF] >> 8) ^ (iL4[(s3) & 0xFF] >> 16) ^ (iL4[(s3 >> 24) & 0xFF] >> 24) ^ rKey[11];

	//r1
	//L2
	s0 = t1 ^ t2 ^ t3;
	s1 = t0 ^ t2 ^ t3;
	s2 = t0 ^ t1 ^ t3;
	s3 = t0 ^ t1 ^ t2;
	//iL1S
	t0 = iL0[(s0 >> 24) & 0xFF] ^ iL1[(s0 >> 16) & 0xFF] ^ iL2[(s0 >> 8) & 0xFF] ^ iL3[s0 & 0xFF] ^ rKey[4];
	t1 = iL0[(s1 >> 24) & 0xFF] ^ iL1[(s1 >> 16) & 0xFF] ^ iL2[(s1 >> 8) & 0xFF] ^ iL3[s1 & 0xFF] ^ rKey[5];
	t2 = iL0[(s2 >> 24) & 0xFF] ^ iL1[(s2 >> 16) & 0xFF] ^ iL2[(s2 >> 8) & 0xFF] ^ iL3[s2 & 0xFF] ^ rKey[6];
	t3 = iL0[(s3 >> 24) & 0xFF] ^ iL1[(s3 >> 16) & 0xFF] ^ iL2[(s3 >> 8) & 0xFF] ^ iL3[s3 & 0xFF] ^ rKey[7];
	//S
	s0 = iL4[(t0 >> 24) & 0xFF] ^ (iL4[(t0 >> 16) & 0xFF] >> 8) ^ (iL4[(t0 >> 8) & 0xFF] >> 16) ^ (iL4[(t0) & 0xFF] >> 24) ^ rKey[0];
	s1 = iL4[(t1) & 0xFF] ^ (iL4[(t1 >> 24) & 0xFF] >> 8) ^ (iL4[(t1 >> 16) & 0xFF] >> 16) ^ (iL4[(t1 >> 8) & 0xFF] >> 24) ^ rKey[1];
	s2 = iL4[(t2 >> 8) & 0xFF] ^ (iL4[(t2) & 0xFF] >> 8) ^ (iL4[(t2 >> 24) & 0xFF] >> 16) ^ (iL4[(t2 >> 16) & 0xFF] >> 24) ^ rKey[2];
	s3 = iL4[(t3 >> 16) & 0xFF] ^ (iL4[(t3 >> 8) & 0xFF] >> 8) ^ (iL4[(t3) & 0xFF] >> 16) ^ (iL4[(t3 >> 24) & 0xFF] >> 24) ^ rKey[3];
	
	PUTU32(out, s0);
	PUTU32(out + 4, s1);
	PUTU32(out + 8, s2);
	PUTU32(out + 12, s3);

	return 1;
}
