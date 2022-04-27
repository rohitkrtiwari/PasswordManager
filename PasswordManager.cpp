/*****************************************************************************************************************
 
File Name: PasswordManager.cpp
File Location: ./PasswordManager.cpp
__________________________________________________________________________________________________________________
 
Purpose: For personal use
Author: Rohit Tiwari
Creation Date: April 2022


*****************************************************************************************************************/




#include "sqlite3.h" // header file for database operations
#include <iostream>
#include <conio.h>
#include <string.h>
#include <sstream>
#include <stdio.h>
#include <iomanip>         // Set field width by setw()
#include "sha256/sha256.h" // Password Hashing
using namespace std;

static int string_to_int[16] = { 0 };
int * strin_to_int(string str)
{
    // cout << str << endl;
    for (int i = 0; i < 16; i++)
    {
        string_to_int[i] = 0;
    }
    int str_length = str.length();
    int j = 0, i, sum = 0;
    for (i = 0; str[i] != '\0'; i++) {
        if (str[i] == ',')
            continue;
         if (str[i] == ' '){
            j++;
        }
        else {
            string_to_int[j] = string_to_int[j] * 10 + (str[i] - 48);
        }
    }
    return string_to_int;
}

// ************************************************************************************************************** //
//										ENCRYPTION DECRYPTION CODE												  //
// ************************************************************************************************************** //

class AES
{
public:
#define Nb 4
    int Nr = 0;
    int Nk = 0;
    unsigned char in[1024], out[1024], state[4][Nb];
    unsigned char RoundKey[240];
    char Key[32] = {0};
    #define xtime(x) ((x << 1) ^ (((x >> 7) & 1) * 0x1b))
    int Rcon[255] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
        0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
        0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d,
        0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
        0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
        0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
        0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
        0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
        0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4,
        0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
        0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
        0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
        0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
        0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
        0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
        0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
        0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83,
        0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
        0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
        0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
        0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
        0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3,
        0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
        0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};

    int getSBoxValue(int num);
    void KeyExpansion();
    void AddRoundKey(int round);
    void setKey();
    void getKey();
};

int AES ::getSBoxValue(int num)
{
    int sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
    return sbox[num];
}
void AES ::KeyExpansion()
{
    int i, j;
    unsigned char temp[4], k;
    for (i = 0; i < Nk; i++)
    {
        RoundKey[i * 4] = Key[i * 4];
        RoundKey[i * 4 + 1] = Key[i * 4 + 1];
        RoundKey[i * 4 + 2] = Key[i * 4 + 2];
        RoundKey[i * 4 + 3] = Key[i * 4 + 3];
    }
    while (i < (Nb * (Nr + 1)))
    {
        for (j = 0; j < 4; j++)
        {
            temp[j] = RoundKey[(i - 1) * 4 + j];
        }
        if (i % Nk == 0)
        {
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;
            temp[0] = getSBoxValue(temp[0]);
            temp[1] = getSBoxValue(temp[1]);
            temp[2] = getSBoxValue(temp[2]);
            temp[3] = getSBoxValue(temp[3]);
            temp[0] = temp[0] ^ Rcon[i / Nk];
        }
        else if (Nk > 6 && i % Nk == 4)
        {
            temp[0] = getSBoxValue(temp[0]);
            temp[1] = getSBoxValue(temp[1]);
            temp[2] = getSBoxValue(temp[2]);
            temp[3] = getSBoxValue(temp[3]);
        }
        RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ temp[0];
        RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ temp[1];
        RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ temp[2];
        RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ temp[3];
        i++;
    }
}
void AES ::AddRoundKey(int round)
{
    int i, j;
    for (i = 0; i < Nb; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
        }
    }
}
void AES ::setKey()
{
    fflush(stdin);
    printf("PRIVATE_KEY: ");
    scanf("%[^\n]%*c", Key);
    fflush(stdin);
}
void AES ::getKey()
{
    fflush(stdin);
    printf("PRIVATE_KEY: %s", Key);
    fflush(stdin);
}

class Encrypt : public AES
{
public:
    int res[1024], res_size = 0;
    void SubBytes();
    void ShiftRows();
    void MixColumns();
    void Cipher();
    int fillBlock(int sz, char *str, unsigned char *in);
    void encrypt(char str[]);
};

void Encrypt ::SubBytes()
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            state[i][j] = getSBoxValue(state[i][j]);
        }
    }
}
void Encrypt ::ShiftRows()
{
    unsigned char temp;
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}
void Encrypt ::MixColumns()
{
    int i;
    unsigned char Tmp, Tm, t;
    for (i = 0; i < Nb; i++)
    {
        t = state[0][i];
        Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
        Tm = state[0][i] ^ state[1][i];
        Tm = xtime(Tm);
        state[0][i] ^= Tm ^ Tmp;

        Tm = state[1][i] ^ state[2][i];
        Tm = xtime(Tm);
        state[1][i] ^= Tm ^ Tmp;

        Tm = state[2][i] ^ state[3][i];
        Tm = xtime(Tm);
        state[2][i] ^= Tm ^ Tmp;

        Tm = state[3][i] ^ t;
        Tm = xtime(Tm);
        state[3][i] ^= Tm ^ Tmp;
    }
}
void Encrypt :: Cipher()
{
    int i, j, round = 0;
    for (i = 0; i < Nb; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[j][i] = in[i * 4 + j];
        }
    }
    AddRoundKey(0);
    for (round = 1; round < Nr; round++)
    {
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
    }
    SubBytes();
    ShiftRows();
    AddRoundKey(Nr);
    for (i = 0; i < Nb; i++)
    {
        for (j = 0; j < 4; j++)
        {
            out[i * 4 + j] = state[j][i];
        }
    }
}
int Encrypt ::fillBlock(int sz, char *str, unsigned char *in)
{
    int j = 0;
    while (sz < strlen(str))
    {
        if (j >= Nb * 4)
            break;
        in[j++] = (unsigned char)str[sz];
        sz++;
    }
    if (sz >= strlen(str))
        for (; j < Nb * 4; j++)
            in[j] = 0;
    return sz;
}
void Encrypt ::encrypt(char str[])
{
    int i;
    Nk = 8;
    Nr = Nk + 6;
    res_size = 0;
    KeyExpansion();
    int sz = 0;
    while (sz < strlen(str))
    {
        sz = fillBlock(sz, str, in);
        Cipher();
        for (i = 0; i < Nb * 4; i++)
        {
            res[i] = (int)out[i];
            res_size++;
        }
    }
}

class Decrypt : public AES
{
public:
    char res[1024];
    int res_size = 0;
#define Multiply(x, y) (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ ((y >> 2 & 1) * xtime(xtime(x))) ^ ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^ ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))))
    void InvSubBytes();
    void InvShiftRows();
    void InvMixColumns();
    void InvCipher();
    void decrypt(int arr[]);
    void print();
    int getSBoxInvert(int num);
};

void Decrypt ::InvSubBytes()
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < Nb; j++)
        {
            state[i][j] = getSBoxInvert(state[i][j]);
        }
    }
}
void Decrypt ::InvShiftRows()
{
    unsigned char temp;
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}
void Decrypt ::InvMixColumns()
{
    int i;
    unsigned char a, b, c, d;
    for (i = 0; i < Nb; i++)
    {
        a = state[0][i];
        b = state[1][i];
        c = state[2][i];
        d = state[3][i];
        state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^
                      Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^
                      Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^
                      Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^
                      Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}
void Decrypt ::InvCipher()
{
    int i, j, round = 0;
    for (i = 0; i < Nb; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[j][i] = in[i * 4 + j];
        }
    }
    AddRoundKey(Nr);
    for (round = Nr - 1; round > 0; round--)
    {
        InvShiftRows();
        InvSubBytes();
        AddRoundKey(round);
        InvMixColumns();
    }
    InvShiftRows();
    InvSubBytes();
    AddRoundKey(0);
    for (i = 0; i < Nb; i++)
    {
        for (j = 0; j < 4; j++)
        {
            out[i * 4 + j] = state[j][i];
        }
    }
}
int Decrypt ::getSBoxInvert(int num)
{
    int rsbox[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
        0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
    return rsbox[num];
}
void Decrypt ::decrypt(int arr[])
{
    int i;
    Nk = 8;
    Nr = Nk + 6;
    res_size = 0;
    KeyExpansion();
    for (int i = 0; i < Nb * 4; i++)
        in[i] = arr[i];

    InvCipher();
    for (i = 0; i < Nb * 4 && out[i] != 0; i++)
    {
        res[i] = (char)out[i];
        res_size++;
    }
}
void Decrypt ::print()
{
    for (int i = 0; i < res_size; i++)
        cout << res[i];
}

// ************************************************************************************************************** //



// ************************************************************************************************************** //
//										       DATABASE CODE           											  //
// ************************************************************************************************************** //

// Database Callback Functions

struct dec_buffer
{
    int id;
    string password;
    string username;
    string service;
};
dec_buffer bf;

int callbackSelect(void *NotUsed, int argc, char **argv, char **azColName)
{
    cout << setw(5) << argv[0] << setw(20) << argv[1] << setw(35) << argv[2] << setw(20) << "*********";
    cout << endl;
    return 0;
}
int callbackSelectPassword(void *NotUsed, int argc, char **argv, char **azColName)
{
    bf.id = (int)argv[0];
    bf.service = argv[1];
    bf.username = argv[2];
    bf.password = argv[3];
    return 0;
}
int callback(void *NotUsed, int argc, char **argv, char **azColName)
{
    for (int i = 0; i < argc; i++)
        cout << azColName[i] << ": " << argv[i] << endl;
    cout << endl;
    return 0;
}
// Database Class
class DataBase
{

private:
    // Database File Location
    const char *s = R"(flower.jpg)";

public:
    // Create Database
    int createDB();
    // Create Table if Not Exists
    int createTable();
    // Insert New Entry in DataBase
    int insertData(std::string &service, std::string &username, std::string &password);
    // Delete Record By ID
    int Delete();
    // Delete Record By ID
    int Delete(int id);
    // Delete Record by Service
    int Delete(string service);
    // Display complete Data with Password Hidden
    int Display();
    // Fetch Passwords with ID
    int Fetch_Password(int id);
};

// Create DB
int DataBase ::createDB()
{
    sqlite3 *DB;
    int exit = 0;
    exit = sqlite3_open(s, &DB);
    sqlite3_close(DB);
    return 0;
}

// Create Table If not exists
int DataBase ::createTable()
{
    sqlite3 *DB;
    char *messageError;
    string sql = "CREATE TABLE IF NOT EXISTS database("
                 "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
                 "service varchar(250) NOT NULL, "
                 "username varchar(250)  NULL, "
                 "password text NOT NULL );";
    try
    {
        int exit = 0;
        exit = sqlite3_open(s, &DB);
        exit = sqlite3_exec(DB, sql.c_str(), NULL, 0, &messageError);
        if (exit != SQLITE_OK)
        {
            cerr << "Error in createTable function." << endl;
            sqlite3_free(messageError);
        }
        else
            cout << "Database Connection Successfull..!" << endl;
        sqlite3_close(DB);
    }
    catch (const exception &e)
    {
        cerr << e.what();
    }
    return 0;
}

// Method for Inserting data in Database
int DataBase ::insertData(std::string &service, std::string &username, std::string &password)
{
    sqlite3 *DB;
    char *messageError;

    string sql = "INSERT INTO database (service, username, password) VALUES('" + service + "', '" + username + "', '" + password + "'); ";

    int exit = sqlite3_open(s, &DB);
    exit = sqlite3_exec(DB, sql.c_str(), NULL, 0, &messageError);
    if (exit != SQLITE_OK)
    {
        sqlite3_free(messageError);
        return 0;
    }
    else
        return 1;
}

// Method To Delete Entries
// Delete Complete Table
int DataBase ::Delete()
{
    sqlite3 *DB;
    char *messageError;
    string sql = "DELETE FROM database;";
    int exit = sqlite3_open(s, &DB);
    exit = sqlite3_exec(DB, sql.c_str(), callback, NULL, &messageError);
    if (exit != SQLITE_OK)
    {
        cerr << "Error in deleteData function." << endl;
        sqlite3_free(messageError);
    }
    else
        cout << "Records deleted Successfully!" << endl;
    return 0;
}

// Delete Single Record by ID
int DataBase ::Delete(int id)
{
    sqlite3 *DB;
    char *messageError;
    string sql = "DELETE FROM database where ID = " + to_string(id) + ";";
    int exit = sqlite3_open(s, &DB);
    exit = sqlite3_exec(DB, sql.c_str(), callback, NULL, &messageError);
    if (exit != SQLITE_OK)
    {
        cerr << "Error in deleteData function." << endl;
        sqlite3_free(messageError);
    }
    else
        cout << "Records deleted Successfully!" << endl;
}

// Delete Single Record by Service
int DataBase ::Delete(string service)
{
    sqlite3 *DB;
    char *messageError;
    string sql = "DELETE FROM database where service = '" + service + "';";
    int exit = sqlite3_open(s, &DB);
    exit = sqlite3_exec(DB, sql.c_str(), callback, NULL, &messageError);
    if (exit != SQLITE_OK)
    {
        cerr << "Error in deleteData function." << endl;
        sqlite3_free(messageError);
    }
    else
        cout << "Records deleted Successfully!" << endl;
}

// Display Complete Table
int DataBase ::Display()
{
    sqlite3 *DB;
    char *messageError;

    string sql = "SELECT * FROM database;";
    int exit = sqlite3_open(s, &DB);
    cout << endl
         << "***************************************************************************************";
    cout << endl
         << setw(5) << "ID" << setw(20) << "SERVICE" << setw(35) << "USERNAME" << setw(20) << "PASSWORD\n";
    cout << "***************************************************************************************\n";
    exit = sqlite3_exec(DB, sql.c_str(), callbackSelect, NULL, &messageError);

    if (exit != SQLITE_OK)
    {
        cerr << "Error in selectData function." << endl;
        sqlite3_free(messageError);
    }
    return 0;
}

// Fetch Single Record Including Password Which have same ID Provided in Method Argument
int DataBase ::Fetch_Password(int id)
{
    Decrypt dec;
    sqlite3 *DB;
    char *messageError;

    string sql = "SELECT * FROM database where ID = " + to_string(id) + ";";
    int exit = sqlite3_open(s, &DB);
    cout << endl
         << "***************************************************************************************";
    cout << endl
         << setw(5) << "ID" << setw(20) << "SERVICE" << setw(35) << "USERNAME" << setw(20) << "PASSWORD\n";
    cout << "***************************************************************************************\n";
    exit = sqlite3_exec(DB, sql.c_str(), callbackSelectPassword, NULL, &messageError);

    if (exit != SQLITE_OK)
    {
        cerr << "Error in selectData function." << endl;
        sqlite3_free(messageError);
    }
    return 0;
}

// ************************************************************************************************************** //



// ************************************************************************************************************** //
//										PASSWORD MANAGER CODE   												  //
// ************************************************************************************************************** //

class PasswordManager
{
private:
    const char *MASTER_PASSWORD = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";

public:
    DataBase db;
    Encrypt enc;
    Decrypt dec;

    bool LoggedIn = false;
    void Login();
    string Scan_Password();
    string Generate(int len);
    void Add();
    void Add(string password);
    void Fetch_Password(int id);
    // void Fetch_Password(string service);
    // void Fetch_Password(string username);
    void Display();
    void Delete();
    void Delete(int id);
    void Menu();
    bool Verify_user();
    string convertToString(int int_array[], int size);
};

void PasswordManager ::Login()
{
    string raw_password;
    raw_password = Scan_Password();
    string password = sha256(raw_password);
    if (password == MASTER_PASSWORD)
    {
        LoggedIn = true;
    }
    else
        LoggedIn = false;
}
bool PasswordManager ::Verify_user()
{
    string raw_password;
    raw_password = Scan_Password();
    string password = sha256(raw_password);
    if (password == MASTER_PASSWORD)
    {
        return true;
    }
    else
        return false;
}
string PasswordManager ::Scan_Password()
{
    string password, P;
    char p;
    // system("cls");
    cout << "Enter Master Password: ";
    p = _getch();
    while (p != 13)
    {
        if (p == 8)
        {
            P.resize(P.length() - 1);
            cout << P;
            password.resize(password.length() - 1);
        }
        else
        {
            P = P + "*";
            cout << P;
            password.push_back(p);
        }
        p = _getch();
        system("cls");
        cout << "Enter Password: ";
    }
    // system("cls");
    return password;
}
string PasswordManager ::Generate(int len)
{
    char letters[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
                      'r', 's', 't', 'u', 'v', 'w', 'x',
                      'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
                      'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                      '&', '@', '#', '$', '&', '@', '#', '$', '!', '*', '?', ':'};

    string ran = "";
    int MAX_SIZE = sizeof(letters);
    for (int i = 0; i < len; i++)
        ran = ran + letters[rand() % MAX_SIZE];

    return ran;
}
void PasswordManager ::Add()
{
    string password, username, service;
    string enc_password;
    cin.clear();
    fflush(stdin);
    cin.sync();
    cout << "passsword: ";
    getline(cin, password);

    cin.clear();
    fflush(stdin);
    cin.sync();
    cout << "Username: ";
    getline(cin, username);

    cin.clear();
    fflush(stdin);
    cin.sync();
    cout << "Service: ";
    getline(cin, service);

    char cstr[password.size() + 1];
    strcpy(cstr, password.c_str());
    enc.encrypt(cstr);

    enc_password = convertToString((enc.res), enc.res_size);

    int status = db.insertData(service, username, enc_password);
    if (status)
        cout << "Records Added Successfully" << endl;
    else
        cout << "ERROR!" << endl;
}
void PasswordManager ::Add(string password)
{
    string username, service;
    string enc_password;

    cin.clear();
    fflush(stdin);
    cin.sync();
    cout << "Username: ";
    getline(cin, username);

    cin.clear();
    fflush(stdin);
    cin.sync();
    cout << "Service: ";
    getline(cin, service);

    char cstr[password.size() + 1];
    strcpy(cstr, password.c_str());
    enc.encrypt(cstr);

    enc_password = convertToString((enc.res), enc.res_size);

    cout << "Encrypted Password: " << enc_password << endl;

    int status = db.insertData(service, username, enc_password);
    if (status)
        cout << "Records Added Successfully" << endl;
    else
        cout << "ERROR!" << endl;
}
void PasswordManager ::Fetch_Password(int id)
{
    /* 
    
    Fetch Password Logic : 

    Step 1 : Verify_user() will asks the user to enter master password before he can fetch a password.

    Step 2 : db.Fetch_Password will fetch the details and store it in the global struct type variable bf (Buffer).

    Step 3 : The password is the bf.password field is in encrypted form and char data type e.g. 12 32 445 6 5 43 23 534.
    
    Step 4 : To decrypt the password we need to convert the char array in bf.password into an integer array.

    Step 5 : the strin_to_int() function will return the address of the array which we'll store in *p.

    Step 6 : then the *p data will be copied to arr[] and arr will passed to the decryption Algo.

    Step 7 : We'll print the result.

    
    */
    if (Verify_user())
    {
        int * p;
        int arr[16] = {0};
        p = NULL;
        db.Fetch_Password(id);
        p = strin_to_int(bf.password);
        for (int i = 0; i < 16; i++)
        {
            arr[i] = *(p + i);
        }
        
        dec.decrypt(arr);

        cout << "Password: ";
        dec.print();
        cout << endl << "Username: " << bf.username << endl;
        cout << "Service: " << bf.service << endl;

    }

}

void PasswordManager :: Delete (int id) {

    cout << "Do you really want to delete the entry ? (Y/N) ";
    char delete_OK;
    cin.clear();
    fflush(stdin);
    cin >> delete_OK;
    if (delete_OK == 'Y' || delete_OK == 'y')
        if (Verify_user())
            db.Delete(id);
}

void PasswordManager :: Delete () {

    cout << "Do you really want to delete the entry ? (Y/N) ";
    char delete_OK;
    cin.clear();
    fflush(stdin);
    cin >> delete_OK;
    if (delete_OK == 'Y' || delete_OK == 'y')
        if (Verify_user())
            db.Delete();
}

string PasswordManager ::convertToString(int int_array[], int size_of_array)
{
    ostringstream oss("");
    for (int temp = 0; temp < size_of_array; temp++)
    {
        oss << int_array[temp];
        oss << " ";
    }
    return oss.str();
}
void PasswordManager ::Display()
{
    db.Display();
}
void PasswordManager ::Menu()
{
    cout << endl
         << "********** PASSWORD MANAGER **********" << endl;
    cout << "1. Generate New password" << endl;
    cout << "2. Add New Password" << endl;
    cout << "3. Get a password" << endl;
    cout << "4. List all the passwords" << endl;
    cout << "5. Delete a Password" << endl;
    cout << "6. Clear Records" << endl;
    cout << "7. Exit" << endl;
    cout << endl
         << ">> ";
}

// ************************************************************************************************************** //

int main()
{
    string password, service;
    bool pass_choosen = false;
    char pass_OK, save_pass_in_db;
    int id;
    int fetch_choice;

    PasswordManager app;
    app.Login();
    if (app.LoggedIn)
    {
        // Create database and Table When Uses First Time
        app.db.createDB();
        app.db.createTable();

        // Sets the keys for both instances of Encryption and Decryption 
        app.enc.setKey();
        strcpy(app.dec.Key, app.enc.Key);
        
        // Main program Interface
        while (app.LoggedIn)
        {
            // Display Menu
            app.Menu();

            // Take the User Option
            int operation;
            cin.clear();
            fflush(stdin);
            cin >> operation;

            // Switch According to the Operation User Wants to perform
            switch (operation)
            {

            // Case 1: If user wants to generate a new Random Password
            case 1:

                // Keep Generating passwords until User Accepts the password

                while (!pass_choosen)
                {
                    password = app.Generate(15);
                    cout << "Password: " << password << endl;
                    cout << "Do you want to go with this password (y/n): ";
                    cin.clear();
                    fflush(stdin);
                    cin >> pass_OK;
                    if (pass_OK == 'Y' || pass_OK == 'y')
                        pass_choosen = true;
                }

                // Ask User if they want to store the newly generated Password in Data Base
                cout << "Would you like to Save the newly Generated Password ? (Y/N): ";
                cin >> save_pass_in_db;

                if (save_pass_in_db == 'Y' || save_pass_in_db == 'y')
                {
                    // If user  enters Y then Run the app.Add() routine which asks for username and service and store in DB
                    app.Add(password);
                }

                pass_choosen = false;

                break;

            case 2:
                app.Add();
                break;

            // Case 3: If user wants to Fetch a saved Password from DB
            case 3:
                // Display the complete table so that user knows the choose ID he wants to fetch password of
                app.Display();

                // Ask user for Record ID
                fflush(stdin);
                cin.clear();
                cout << "Password ID: ";
                cin >> id;

                // Fetch the Data
                app.Fetch_Password(id);
                break;

            case 4:
                // Display the complete table 
                app.Display();
                break;

            case 5:

                // Display the complete table 
                app.Display();
            
                // Ask user for Record ID
                fflush(stdin);
                cin.clear();
                cout << "Record ID: ";
                cin >> id;

                // Delete Record by ID 
                app.Delete(id);
                break;

            case 6:
                // Display the complete table 
                app.Display();

                // Clear complete Database 
                app.Delete();
                break;

            case 7:
                cout << endl << "Bye!" << endl;
                exit(0);
                break;
            }

            // exit(0);
        }
    }

    else
        cout << "Wrong Password";
}
