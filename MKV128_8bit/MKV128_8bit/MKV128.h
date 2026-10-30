typedef unsigned char u8;

#define n 4
#define BlockLength 16 //byte
#define Round128 7
#define Round192 8
#define Round256 9


//f(x) = x^8 + x^5 + x^3 + x + 1
/*
u8 X[4][4] = {
        {0, 1, 0, 0},
        {0, 0, 1, 0},
        {0, 0, 0, 1},
        {1, 2, 1, 3}
    };


u8 M[4][4] = {//= X^4
    {0x01, 0x02, 0x01, 0x03},
    {0x03, 0x07, 0x01, 0x04},
    {0x04, 0x0B, 0x03, 0x0D},
    {0x0D, 0x1E, 0x06, 0x14}
};

u8 Y[4][4] = {
        {2, 1, 3, 1},
        {1, 0, 0, 0},
        {0, 1, 0, 0},
        {0, 0, 1, 0}
    };

u8 iM[4][4] = { //= Y^4
    {0x14, 0x06, 0x18, 0x0B},
    {0x0B, 0x02, 0x0D, 0x05},
    {0x05, 0x01, 0x07, 0x02},
    {0x02, 0x01, 0x03, 0x01}
};
*/

//Encrypt/Decrypt one 128 bit block 
void EncryptOneBlock128(int r, u8* X, u8* Key, u8* Y);
void DecryptOneBlock128(int r, u8* X, u8* Key, u8* Y);

//Key Init 
void setInitialKeyState128(int r, u8* K, u8* Block1, u8* Block2);

//Key schedule
void KeyExpansion128(int round, u8* MasterKey, u8* rKey);
void KeyExpansion128_testvector(int round, u8* MasterKey, u8* rKey);