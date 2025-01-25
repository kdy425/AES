#include<stdio.h>
#include<assert.h>
#include<stdlib.h>
#include "AES.h"
#include<time.h>
#include<memory.h>

#define MUL2(a) (a << 1)^(a & 0x80 ? 0x1b : 0x00) //x 를 곱하는 부분 => 0x02
#define MUL3(a) (MUL2(a))^(a) // 3 을 곱하는 부분
#define MUL4(a) MUL2((MUL2(a)))
#define MUL8(a) MUL2((MUL2((MUL2(a)))))
#define MUL9(a) (MUL8(a))^(a)
#define MULB(a) (MUL8(a))^(MUL2(a))^(a)
#define MULD(a) (MUL8(a))^(MUL4(a))^(a)
#define MULE(a) (MUL8(a))^(MUL4(a))^(MUL2(a))

u8 MSBox[256] = { 0, };


u8 MUL(u8 a, u8 b) { // 곱셈 구현 => a * b = c 
	u8 r = 0;
	u8 tmp = b;
	u32 i;
	for (i = 0; i < 8; i++) {
		if (a & 1) //끝에 한비트가 1인 경우
			r = r ^ tmp;
		tmp = MUL2(tmp);
		a = a >> 1;
	}
	return r;
}

void AddRoundKey(u8 S[16], u8 RK[16]) { // 16byte 입력 들어오면 두개를 xor 해서 temp 에 담는다
	S[0] = S[0] ^ RK[0];
	S[1] = S[1] ^ RK[1];
	S[2] = S[2] ^ RK[2];
	S[3] = S[3] ^ RK[3];
	S[4] = S[4] ^ RK[4];
	S[5] = S[5] ^ RK[5];
	S[6] = S[6] ^ RK[6];
	S[7] = S[7] ^ RK[7];
	S[8] = S[8] ^ RK[8];
	S[9] = S[9] ^ RK[9];
	S[10] = S[10] ^ RK[10];
	S[11] = S[11] ^ RK[11];
	S[12] = S[12] ^ RK[12];
	S[13] = S[13] ^ RK[13];
	S[14] = S[14] ^ RK[14];
	S[15] = S[15] ^ RK[15];

}

void MSubBytes(u8 S[16]) { // 16 bytes 입력 들어오면 각입력 sbox 대치 해서 출력
	S[0] = MSBox[S[0]];
	S[1] = MSBox[S[1]];
	S[2] = MSBox[S[2]];
	S[3] = MSBox[S[3]];
	S[4] = MSBox[S[4]];
	S[5] = MSBox[S[5]];
	S[6] = MSBox[S[6]];
	S[7] = MSBox[S[7]];
	S[8] = MSBox[S[8]];
	S[9] = MSBox[S[9]];
	S[10] = MSBox[S[10]];
	S[11] = MSBox[S[11]];
	S[12] = MSBox[S[12]];
	S[13] = MSBox[S[13]];
	S[14] = MSBox[S[14]];
	S[15] = MSBox[S[15]];
}

void ShiftRows(u8 S[16]) { // 16 bytes shift 한 값
	u8 temp;
	temp = S[1]; // first row
	S[1] = S[5];
	S[5] = S[9];
	S[9] = S[13];
	S[13] = temp;
	temp = S[2]; //second row
	S[2] = S[10];
	S[10] = temp;
	temp = S[6];
	S[6] = S[14];
	S[14] = temp;
	temp = S[15]; // third row  
	S[15] = S[11];
	S[11] = S[7];
	S[7] = S[3];
	S[3] = temp;

}

void MixColumns(u8 S[16]) { // state 각 열을 섞음
	u8 temp[16];
	int i;

	for (i = 0; i < 16; i = i + 4) {
		temp[i] = MUL2(S[i]) ^ MUL3(S[i + 1]) ^ S[i + 2] ^ S[i + 3];
		temp[i + 1] = S[i] ^ MUL2(S[i + 1]) ^ MUL3(S[i + 2]) ^ S[i + 3];
		temp[i + 2] = S[i] ^ S[i + 1] ^ MUL2(S[i + 2]) ^ MUL3(S[i + 3]);
		temp[i + 3] = MUL3(S[i]) ^ S[i + 1] ^ S[i + 2] ^ MUL2(S[i + 3]);
	}
	S[0] = temp[0]; S[1] = temp[1]; S[2] = temp[2]; S[3] = temp[3];
	S[4] = temp[4]; S[5] = temp[5]; S[6] = temp[6]; S[7] = temp[7];
	S[8] = temp[8]; S[9] = temp[9]; S[10] = temp[10]; S[11] = temp[11];
	S[12] = temp[12]; S[13] = temp[13]; S[14] = temp[14]; S[15] = temp[15];
}



void AES_ENC_masking(u8 PT[16], u8 RK[], u8 CT[16], int keysize, u8 m[10]) {
	int Nr = keysize / 32 + 6; // 라운드수 계산
	int i;
	u8 temp[16];

	for (i = 0; i < 16; i++) {
		temp[i] = PT[i];
	}

	for (i = 0; i < 16; i+=4) {
		temp[i] ^= m[6];
		temp[i + 1] ^= m[7];
		temp[i + 2] ^= m[8];
		temp[i + 3] ^= m[9];
	}


	AddRoundKey(temp, RK); // temp의 16byte 와 RK의 첫 16byte를 xor 하여 temp 에 결과를 담는 함수 , 0 라운드

	for (i = 0; i < Nr - 1; i++) {
		MSubBytes(temp);
		ShiftRows(temp);
		for (int j = 0; j < 16; j+=4) {
			temp[j] ^= m[2] ^ m[1];
			temp[j + 1] ^= m[3] ^ m[1];
			temp[j + 2] ^= m[4] ^ m[1];
			temp[j + 3] ^= m[5] ^ m[1];
		}
		MixColumns(temp);
		AddRoundKey(temp, RK + 16 * (i + 1));
	}

	MSubBytes(temp);
	ShiftRows(temp);
	AddRoundKey(temp, RK + 16 * (i + 1));
	for (int j = 0; j < 16; j+=4) {
		temp[j] ^= m[0] ^ m[1] ^ m[6];
		temp[j + 1] ^= m[0] ^ m[1] ^ m[7];
		temp[j + 2] ^= m[0] ^ m[1] ^ m[8];
		temp[j + 3] ^= m[0] ^ m[1] ^ m[9];
	}

	for (i = 0; i < 16; i++) {
		CT[i] = temp[i];
	}
}



u32 u4byte_in(u8* x) {
	return (x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3]; // x[0] || x[1] || x[2] || x[3]
}
void u4byte_out(u8* x, u32 y) {
	x[0] = (y >> 24) & 0xff;
	x[1] = (y >> 16) & 0xff;
	x[2] = (y >> 8) & 0xff;
	x[3] = y & 0xff;
}

void AES_KeyWordToByte(u32 W[], u8 RK[]) {
	int i;
	for (i = 0; i < 44; i++) {
		u4byte_out(RK + 4 * i, W[i]); // RK[4i] || RK[4i + 1] || RK[4i + 2] || RK[4i + 3] <--W[i]
	}
}

u32 Rcons[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };

#define RotWord(x) ((x << 8) | (x >> 24))

#define SubWord(x)								\
	((u32)Sbox[(u8)(x >> 24)] << 24)			\
	| ((u32)Sbox[(u8)((x >> 16) & 0xff)] << 16)	\
	| ((u32)Sbox[(u8)((x >> 8) & 0xff)] << 8)		\
	| ((u32)Sbox[(u8)(x & 0xff)])				\



void RoundKeyGeneration128_masking(u8 MK[], u8 RK[], u8 m[]) {
	u32 W[44]; //4 * 11
	int i;
	u32 T;
	W[0] = u4byte_in(MK); // W[0] = MK[0] || MK[1] || MK[2] || MK[3]
	W[1] = u4byte_in(MK + 4);
	W[2] = u4byte_in(MK + 8);
	W[3] = u4byte_in(MK + 12);

	for (i = 0; i < 10; i++) {
		//T = G_func(W[4 * i + 3]);
		T = W[4 * i + 3];
		T = RotWord(T);
		T = SubWord(T);
		T = T ^ Rcons[i];

		W[4 * i + 4] = W[4 * i] ^ T;
		W[4 * i + 5] = W[4 * i + 1] ^ W[4 * i + 4];
		W[4 * i + 6] = W[4 * i + 2] ^ W[4 * i + 5];
		W[4 * i + 7] = W[4 * i + 3] ^ W[4 * i + 6];
	}
	AES_KeyWordToByte(W, RK);

	for (i = 0; i < 44; i++) {
		RK[4 * i] ^= m[0] ^ m[6];
		RK[4 * i + 1] ^= m[0] ^ m[7];
		RK[4 * i + 2] ^= m[0] ^ m[8];
		RK[4 * i + 3] ^= m[0] ^ m[9];
	}
}


void AES_keySchedule_masking(u8 MK[], u8 RK[], int keysize, u8 m[]) {
	if (keysize == 128) RoundKeyGeneration128_masking(MK, RK, m);
	//if (keysize == 192) RoundKeyGeneration192(MK, RK);
	//if (keysize == 256) RoundKeyGeneration256(MK, RK);
}



int main() {
	int i;
	u8 PT[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	//u8 PT[16] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a }; //평문
	u8 MK[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
	//u8 MK[16] = { 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; //master key
	u8 CT[16] = { 0x00, }; // 암호문
	u8 RK[240] = { 0x00, }; //round key
	int keysize = 128;
	u8 temp;
	u8 m[10];


	//난수 6개 생성 - m, m', m1, m2, m3, m4 =>  m1', m2', m3' m4'
	srand(time(NULL));
	m[0] = rand();	//m
	m[1] = rand();	//m'
	m[2] = rand();	//m1
	m[3] = rand();	//m2
	m[4] = rand();	//m3
	m[5] = rand();	//m4

	m[6] = MUL2(m[2]) ^ MUL3(m[3]) ^ m[4] ^ m[5];	//m1'
	m[7] = m[2] ^ MUL2(m[3]) ^ MUL3(m[4]) ^ m[5];	//m2'
	m[8] = m[2] ^ m[3] ^ MUL2(m[4]) ^ MUL3(m[5]);	//m3'
	m[9] = MUL3(m[2]) ^ m[3] ^ m[4] ^ MUL2(m[5]);	//m4'



	AES_keySchedule_masking(MK, RK, keysize, m);
	for (i = 0; i < 256; i++) {
		MSBox[(u8)i ^ m[0]] = Sbox[i] ^ m[1];
	}
	AES_ENC_masking(PT, RK, CT, keysize, m);

	printf("making : \n");
	for (i = 0; i < 16; i++) {
		printf("%02x ", CT[i]);
	}
	printf("\n");

	return 0;
}