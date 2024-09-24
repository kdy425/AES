#include<stdio.h>
#include<assert.h>
#include<stdlib.h>
#include "AES.h"

#define MUL2(a) (a << 1)^(a & 0x80 ? 0x1b : 0x00) //x 를 곱하는 부분 => 0x02
#define MUL3(a) (MUL2(a))^(a) // 3 을 곱하는 부분
#define MUL4(a) MUL2((MUL2(a)))
#define MUL8(a) MUL2((MUL2((MUL2(a)))))
#define MUL9(a) (MUL8(a))^(a)
#define MULB(a) (MUL8(a))^(MUL2(a))^(a)
#define MULD(a) (MUL8(a))^(MUL4(a))^(a)
#define MULE(a) (MUL8(a))^(MUL4(a))^(MUL2(a))
u32 Rcons[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };
#define RotWord(x) ((x << 8) | (x >> 24))

#define SubWord(x)								\
	((u32)Sbox[(u8)(x >> 24)] << 24)			\
	| ((u32)Sbox[(u8)((x >> 16) & 0xff)] << 16)	\
	| ((u32)Sbox[(u8)((x >> 8) & 0xff)] << 8)		\
	| ((u32)Sbox[(u8)(x & 0xff)])				\





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

void RoundKeyGeneration128(u8 MK[], u8 RK[]) {
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
}


void MixColumns(u8 S[16]) { // state 각 열을 섞음
	u8 temp[16];
	int i;

	for (i = 0; i < 16; i = i + 4) {
		temp[i] = MULE(S[i]) ^ MULB(S[i + 1]) ^ MULD(S[i + 2]) ^ MUL9(S[i + 3]);
		temp[i + 1] = MUL9(S[i]) ^ MULE(S[i + 1]) ^ MULB(S[i + 2]) ^ MULD(S[i + 3]);
		temp[i + 2] = MULD(S[i]) ^ MUL9(S[i + 1]) ^ MULE(S[i + 2]) ^ MULB(S[i + 3]);
		temp[i + 3] = MULB(S[i]) ^ MULD(S[i + 1]) ^ MUL9(S[i + 2]) ^ MULE(S[i + 3]);
	}
	S[0] = temp[0]; S[1] = temp[1]; S[2] = temp[2]; S[3] = temp[3];
	S[4] = temp[4]; S[5] = temp[5]; S[6] = temp[6]; S[7] = temp[7];
	S[8] = temp[8]; S[9] = temp[9]; S[10] = temp[10]; S[11] = temp[11];
	S[12] = temp[12]; S[13] = temp[13]; S[14] = temp[14]; S[15] = temp[15];
}


void SubBytes(u8 S[16]) { // 16 bytes 입력 들어오면 각입력 Sbox_inverse 대치 해서 출력
	S[0] = Sbox_inverse[S[0]];
	S[1] = Sbox_inverse[S[1]];
	S[2] = Sbox_inverse[S[2]];
	S[3] = Sbox_inverse[S[3]];
	S[4] = Sbox_inverse[S[4]];
	S[5] = Sbox_inverse[S[5]];
	S[6] = Sbox_inverse[S[6]];
	S[7] = Sbox_inverse[S[7]];
	S[8] = Sbox_inverse[S[8]];
	S[9] = Sbox_inverse[S[9]];
	S[10] = Sbox_inverse[S[10]];
	S[11] = Sbox_inverse[S[11]];
	S[12] = Sbox_inverse[S[12]];
	S[13] = Sbox_inverse[S[13]];
	S[14] = Sbox_inverse[S[14]];
	S[15] = Sbox_inverse[S[15]];
}

void ShiftRows(u8 S[16]) { // 16 bytes shift 한 값
	u8 temp;
	temp = S[13]; // 1st row
	S[13] = S[9];
	S[9] = S[5];
	S[5] = S[1];
	S[1] = temp;

	temp = S[2];	//second row
	S[2] = S[10];
	S[10] = temp;
	temp = S[6];
	S[6] = S[14];
	S[14] = temp;

	temp = S[3]; // 3rd row
	S[3] = S[7];
	S[7] = S[11];
	S[11] = S[15];
	S[15] = temp;
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

void AES_DEC(u8 PT[16], u8 RK[], u8 CT[16], int keysize) {
	int Nr = keysize / 32 + 6; // 라운드수 계산
	int i;
	u8 temp[16];

	for (i = 0; i < 16; i++) {
		temp[i] = CT[i];
	}


	AddRoundKey(temp, RK + 16 * (Nr)); // temp의 16byte 와 RK의 첫 16byte를 xor 하여 temp 에 결과를 담는 함수 , 0 라운드
	ShiftRows(temp);
	SubBytes(temp);

	for (i = Nr - 1; i > 0; i--) {
		AddRoundKey(temp, RK + 16 * (i));
		MixColumns(temp);
		ShiftRows(temp);
		SubBytes(temp);
	}

	AddRoundKey(temp, RK);

	for (i = 0; i < 16; i++) {
		PT[i] = temp[i];
	}
}


void AES_keySchedule(u8 MK[], u8 RK[], int keysize) {
	if (keysize == 128) RoundKeyGeneration128(MK, RK);
	//if (keysize == 192) RoundKeyGeneration192(MK, RK);
	//if (keysize == 256) RoundKeyGeneration256(MK, RK);


}

int main() {
	int i;
	//u8 PT[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	//u8 PT[16] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a }; //평문
	u8 MK[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
	//u8 MK[16] = { 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c }; //master key
	//u8 CT[16] = { 0x00, }; // 암호문
	u8 RK[240] = { 0x00, }; //round key
	u8 CT[16] = { 0x25, 0x8d, 0x70, 0x09, 0xef, 0x94, 0xc3, 0x92, 0xf3, 0x94, 0x33, 0x45, 0x3e, 0xf3, 0x4f, 0x41 };
	u8 PT[16] = { 0x00, };
	int keysize = 128;

	AES_keySchedule(MK, RK, keysize); //1round : RK 0~15, 2round : 16~31   마스터키로부터 라운드키를 순차적으로 담는 함수
	AES_DEC(PT, RK, CT, keysize);
	for (i = 0; i < 16; i++) {
		printf("%02x ", PT[i]);
	}
	printf("\n");

	/*a = 0xab;
	b = 0x38;
	c = MUL(a, b);
	printf("%02x * %02x = %02x", a, b, c);
	printf("Sbox(%02x) = %02x\n", a, GenSbox(a));

	printf("Sbox(%02x) = %02x, %02x\n", a, GenSbox(a), Sbox[a]);
	printf("Sbox[256] = \n")
	for (i = 0; i < 256; i++) { // sbox 만들기
		printf("0x%02x, %02x\n ", GenSbox((u8)i));
		if (i % 16 == 15)
			printf("\n");
	}*/

	return 0;
}