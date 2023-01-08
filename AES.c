#include<stdio.h>
#include<assert.h>
#include<stdlib.h>
#include "AES.h"

#define MUL2(a) (a << 1)^(a & 0x80 ? 0x1b : 0x00) //x 를 곱하는 부분
#define MUL3(a) (MUL2(a))^(a) // 3 을 곱하는 부분
#define MUL4(a) MUL2((MUL2(a)))
#define MUL8(a) MUL2((MUL2((MUL2(a)))))
#define MUL9(a) (MUL8(a))^(a)
#define MULB(a) (MUL8(a))^(MUL2(a))^(a)
#define MULD(a) (MUL8(a))^(MUL4(a))^(a)
#define MULE(a) (MUL8(a))^(MUL4(a))^(MUL2(a))

u8 MUL(u8 a, u8 b) { // 곱셈 구현
	u8 r = 0;
	u8 tmp = b;
	u32 i;
	for (i = 0; i < 8; i++) {
		if (a & 1) r ^= tmp;
		tmp = MUL2(tmp);
		a = a >> 1;
	}
	return r;
}
u8 inv(u8 a) { //역원 계산 해서 8비트 담음
	u8 r = a;
	r = MUL(r, r); // r = a2
	r = MUL(r, a); // r = a3
	r = MUL(r, r); // r = a6
	r = MUL(r, a); // r = a7
	r = MUL(r, r); // r = a14
	r = MUL(r, a); // r = a15
	r = MUL(r, r); // r = a30
	r = MUL(r, a); // r = a31
	r = MUL(r, r); // r = a62
	r = MUL(r, a); // r = a63
	r = MUL(r, r); // r = a126 
	r = MUL(r, a); // r = a127
	r = MUL(r, r); // r = a254
	return r;
}
u8 GenSbox(u8 a) { // generate Sbox
	u8 r = 0;
	u8 tmp;
	tmp = inv(a);
	if (tmp & 1) // inv 결과값, 최하위 비트가 1 이면
		r = r ^ 0x1f;
	if (tmp & 2) // tmp의 2번째 비트가 1 이면
		r = r ^ 0x3e;
	if (tmp & 4) // 3번째 ( 4 = 0000 0010)
		r = r ^ 0x7c;
	if (tmp & 8) // 4번째
		r = r ^ 0xf8;
	if (tmp & 16)
		r = r ^ 0xf1;
	if (tmp & 32)
		r = r ^ 0xe3;
	if (tmp & 64)
		r = r ^ 0xc7;
	if (tmp & 128)
		r = r ^ 0x8f;
	return r ^ 0x63;
}
void AddRoundKey(u8 S[16],u8 RK[16]) { // 16byte 입력 들어오면 두개를 xor 해서 temp 에 담는다
	S[0] = S[0] ^ RK[0]; S[1] = S[1] ^ RK[1]; S[2] = S[2] ^ RK[2]; S[3] = S[3] ^ RK[3];
	S[4] = S[4] ^ RK[4]; S[5] = S[5] ^ RK[5]; S[6] = S[6] ^ RK[6]; S[7] = S[7] ^ RK[7];
	S[8] = S[8] ^ RK[8]; S[9] = S[9] ^ RK[9]; S[10] = S[10] ^ RK[10]; S[11] = S[11] ^ RK[11];
	S[12] = S[12] ^ RK[12]; S[13] = S[13] ^ RK[13]; S[14] = S[14] ^ RK[14]; S[15] = S[15] ^ RK[15];

}

void SubBytes(u8 S[16]) { // 16 bytes 입력 들어오면 각입력 sbox 대치 해서 출력
	S[0] = Sbox[S[0]];
	S[1] = Sbox[S[1]];
	S[1] = Sbox[S[2]];
	S[1] = Sbox[S[3]];
	S[1] = Sbox[S[4]];
	S[1] = Sbox[S[5]];
	S[1] = Sbox[S[6]];
	S[0] = Sbox[S[7]];
	S[1] = Sbox[S[8]];
	S[1] = Sbox[S[9]];
	S[1] = Sbox[S[10]];
	S[1] = Sbox[S[11]];
	S[1] = Sbox[S[12]];
	S[1] = Sbox[S[13]];
	S[0] = Sbox[S[14]];
	S[1] = Sbox[S[15]];
	S[1] = Sbox[S[16]];
}

void ShiftRows(u8 S[16]) { // 16 bytes shift 한 값
	u8 temp;
	temp = S[1]; S[1] = S[5]; S[5] = S[9]; S[9] = S[13]; S[13] = temp; //first row
	temp = S[2]; S[2] = S[10]; S[10] = temp; temp = S[6]; S[6] = S[14]; S[14] = temp; //second row
	temp = S[15];  S[15] = S[11]; S[11] = S[7]; S[7] = S[3]; S[3] = temp; // third row

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



void AES_ENC(u8 PT[16], u8 RK[], u8 CT[16], int keysize) {
	int Nr = keysize / 32 + 6;
	int i;
	u8 temp[16];

	for (i = 0; i < 16; i++) {
		temp[i] = PT[i];
	}




	AddRoundKey(temp, RK); // temp의 16byte 와 RK의 첫 16byte를 xor 하여 temp 에 결과를 담는 함수

	for (i = 0; i < Nr - 1; i++) {
		SubBytes(temp);
		ShiftRows(temp);
		MixColumns(temp);
		AddRoundKey(temp, RK + 16 * (i + 1));
	}

	SubBytes(temp);
	ShiftRows(temp);
	AddRoundKey(temp, RK + 16 * (i + 1));

	for (i = 0; i < 16; i++) {
		CT[i] = temp[i];
	}
}


u32 u4byte_in(u8 *x) {
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

#define SubWord(x)							\
((u32)Sbox[(u8)(x >> 24)] << 24)			\
| ((u32)Sbox[(u8)(x >> 16 & 0xff)] << 16)	\
| ((u32)Sbox[(u8)(x >> 8 & 0xff)] << 8)		\
| ((u32)Sbox[(u8)(x & 0xff)])				\



	void RoundKeyGeneration128(u8 MK[], u8 RK[]) {
		u32 W[44];
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
	}




void AES_keySchedule(u8 MK[], u8 RK[], int keysize) {
	if (keysize == 128) RoundKeyGeneration128(MK, RK);
	//if (keysize == 192) RoundKeyGeneration192(MK, RK);
	//if (keysize == 256) RoundKeyGeneration256(MK, RK);

	
}



int main() {
	int i;
	u8 PT[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	u8 MK[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
	u8 CT[16] = { 0x00, };
	u8 RK[240] = { 0x00, };
	int keysize = 126;

	AES_keySchedule(MK, RK, keysize); //1round : RK 0~15, 2round : 16~31
	AES_ENC(PT, RK, CT, keysize);
	for (i = 0; i < 16; i++) {
		printf("%02x ", CT[i]);
	}
	printf("\n");

	//a = 0xab;
	//b = 0x38;
	//c = MUL(a, b);
	//printf("%02x * %02x = %02x", a, b, c);
	//printf("Sbox(%02x) = %02x\n", a, GenSbox(a));

	//printf("Sbox(%02x) = %02x, %02x\n", a, GenSbox(a), Sbox[a]);
	//printf("Sbox[256] = \n")
	//for (i = 0; i < 256; i++) { // sbox 만들기
	//	printf("0x%02x, %02x\n ", GenSbox((u8)i));
	//	if (i % 16 == 15)
	//		printf("\n");
	//}

	return 0;
}