#include "stdio.h"
#include <stdlib.h>
#include "time.h"

typedef unsigned char u8;
typedef unsigned int u32;

#include "MKV128.h"

u8 Plaintext[16] = {
		0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
		0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00
};
const u8 MasterKey[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

void printState128(u32* A) {
	printf("%08X %08X %08X %08X\n", A[0], A[1], A[2], A[3]);
}

void Test_MKV128(int keyLen, const u8* key, u8* data) {
	int r;
	if (keyLen == KeyLen128) {
		printf("\n ================= MKV 128-128 (Platform 32 BIT) =====================\n\n");
		r = Round128;
	}
	if (keyLen == KeyLen192) {
		printf("\n ================= MKV 128-192 (Platform 32 BIT) =====================\n\n");
		r = Round192;
	}
	if (keyLen == KeyLen256) {
		printf("\n ================= MKV 128-256 (Platform 32 BIT) =====================\n\n");
		r = Round256;
	}
	int i;
	u8 X[16];
	for (int i = 0; i < BlockLength; i++) X[i] = data[i];
	

	printf("Planttext: ");
	for (i = 0; i < BlockLength; i++) printf("%02X ", X[i]);
	printf("\nMaster key: ");
	for (i = 0; i < keyLen/8; i++) printf("%02X ", key[i]);

	u32 rKey[(2 * Round256 + 1) * 4] = { 0, }, irKey[(2 * Round256 + 1) * 4] = { 0, };
	printf("\nRound key:\n");
	KeyExpansion128(keyLen, key, rKey);

	/*
		int t = 0;
	for (i = 0; i < (2 * r + 1) * 4; i += 4) {
		int j = i / 4;
		if (j % 2 == 0) j = 0;
		else j = 1;
		printf("K%d%d: ", t, j);
		printState128(rKey + i);
		if (j == 1)	t++;
	}
	
	*/


	InvKeyExpansion128(keyLen, key, irKey);

	u8 Y[16];
	EncryptOneBlock128(keyLen, rKey, X, Y);
	printf("Ciphertext: ");
	for (i = 0; i < BlockLength; i++) printf("%02X ", Y[i]);
	printf("\n\n");
	DecryptOneBlock128(keyLen, irKey, Y, X);
	printf("Planttext*: ");
	for (i = 0; i < BlockLength; i++) printf("%02X ", X[i]);
	printf("\n\n");

	printf("\n ================= SPEED TEST =====================\n");

	u32 k;
	clock_t tim;
	tim = clock();
	for (k = 0; k < 20000000; k++) {
		EncryptOneBlock128(keyLen, rKey, X, X);
	}
	tim = clock() - tim;
	double duration = (double)(tim) / CLOCKS_PER_SEC;
	duration = (float)2441 / duration;
	printf(" Encryption speed of MKV 128-%d: %f Mbit/seconds", keyLen, duration);

	tim = clock();
	for (k = 0; k < 20000000; k++) {
		DecryptOneBlock128(keyLen, irKey, X, X);
	}
	tim = clock() - tim;
	duration = (double)(tim) / CLOCKS_PER_SEC;
	duration = (float)2441 / duration;
	printf("\n Decryption speed of MKV 128-%d: %f Mbit/seconds", keyLen, duration);
	printf("\nEnd\n");
}

int main() 
{
	//Test_MKV128(KeyLen128, MasterKey, Plaintext);
	//Test_MKV128(KeyLen192, MasterKey, Plaintext);
	Test_MKV128(KeyLen256, MasterKey, Plaintext);

	getchar();
	return 1;
}