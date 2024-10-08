#include<stdio.h>
#include<assert.h>
#include<stdlib.h>
#include "AES.h"
#include<time.h>

#define MUL2(a) (a << 1)^(a & 0x80 ? 0x1b : 0x00) //x 를 곱하는 부분 => 0x02
#define MUL3(a) (MUL2(a))^(a) // 3 을 곱하는 부분
#define MUL4(a) MUL2((MUL2(a)))
#define MUL8(a) MUL2((MUL2((MUL2(a)))))
#define MUL9(a) (MUL8(a))^(a)
#define MULB(a) (MUL8(a))^(MUL2(a))^(a)
#define MULD(a) (MUL8(a))^(MUL4(a))^(a)
#define MULE(a) (MUL8(a))^(MUL4(a))^(MUL2(a))

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
u8 inv(u8 a) { //역원 계산 해서 8비트 담음   254제곱 구하기  inversion
	u8 r = a;
	r = MUL(r, r); // r = a^2
	r = MUL(r, a); // r = a^3
	r = MUL(r, r); // r = a^6
	r = MUL(r, a); // r = a^7
	r = MUL(r, r); // r = a^14
	r = MUL(r, a); // r = a^15
	r = MUL(r, r); // r = a^30
	r = MUL(r, a); // r = a^31
	r = MUL(r, r); // r = a^62
	r = MUL(r, a); // r = a^63
	r = MUL(r, r); // r = a^126 
	r = MUL(r, a); // r = a^127
	r = MUL(r, r); // r = a^254
	return r;
}
u8 GenSbox(u8 a) { // generate Sbox,  affine transformation
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

void SubBytes(u8 S[16]) { // 16 bytes 입력 들어오면 각입력 sbox 대치 해서 출력
	S[0] = Sbox[S[0]];
	S[1] = Sbox[S[1]];
	S[2] = Sbox[S[2]];
	S[3] = Sbox[S[3]];
	S[4] = Sbox[S[4]];
	S[5] = Sbox[S[5]];
	S[6] = Sbox[S[6]];
	S[7] = Sbox[S[7]];
	S[8] = Sbox[S[8]];
	S[9] = Sbox[S[9]];
	S[10] = Sbox[S[10]];
	S[11] = Sbox[S[11]];
	S[12] = Sbox[S[12]];
	S[13] = Sbox[S[13]];
	S[14] = Sbox[S[14]];
	S[15] = Sbox[S[15]];
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



void AES_ENC(u8 PT[16], u8 RK[], u8 CT[16], int keysize) {
	int Nr = keysize / 32 + 6; // 라운드수 계산
	int i;
	u8 temp[16];

	for (i = 0; i < 16; i++) {
		temp[i] = PT[i];
	}




	AddRoundKey(temp, RK); // temp의 16byte 와 RK의 첫 16byte를 xor 하여 temp 에 결과를 담는 함수 , 0 라운드

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



u32 u4byte_in(u8* x) {
	return (x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3]; // x[0] || x[1] || x[2] || x[3]
}
void u4byte_out(u8* x, u32 y) {	//32비트를 쪼개서 8비트에 넣는 함수
	x[0] = (y >> 24) & 0xff;
	x[1] = (y >> 16) & 0xff;
	x[2] = (y >> 8) & 0xff;
	x[3] = y & 0xff;
}


void AES_ENC_Optimization(u8 PT[16], u32 W[], u8 CT[16], int keysize) {
	int Nr = keysize / 32 + 6; // 라운드수 계산
	int i;
	u32 s0, s1, s2, s3, t0, t1, t2, t3;

	//0round
	s0 = u4byte_in(PT) ^ W[0];	//PT 의 시작 주소부터 4 바이트로 묶어서 32 바이트로 리턴
	s1 = u4byte_in(PT + 4) ^ W[1];
	s2 = u4byte_in(PT + 8) ^ W[2];
	s3 = u4byte_in(PT + 12) ^ W[3];	

	//1round
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[4];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[5];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[6];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[7];

	//2round
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[8];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[9];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[10];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[11];

	//3round
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[12];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[13];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[14];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[15];
	
	//4round
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[16];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[17];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[18];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[19];

	//5round
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[20];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[21];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[22];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[23];
	
	//6round
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[24];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[25];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[26];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[27];

	//7round
	t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[28];
	t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[29];
	t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[30];
	t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[31];
	
	//8round
	s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[32];
	s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[33];
	s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[34];
	s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[35];

	if (Nr == 10) {
		//9round
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[36];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[37];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[38];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[39];
		
		//10round
		s0 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[40];
		s1 = (Te2[t1 >> 24] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t0 & 0xff] & 0x000000ff) ^ W[41];
		s2 = (Te2[t2 >> 24] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t1 & 0xff] & 0x000000ff) ^ W[42];
		s3 = (Te2[t3 >> 24] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t2 & 0xff] & 0x000000ff) ^ W[43];

	}

	else if (Nr == 12) {
		//9round
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[36];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[37];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[38];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[39];

		//10round
		s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[40];
		s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[41];
		s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[42];
		s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[43];

		//11round
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[44];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[45];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[46];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[47];

		//12round
		s0 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[48];
		s1 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[49];
		s2 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[50];
		s3 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[51];

	}

	else if (Nr = 14) {
		//9round
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[36];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[37];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[38];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[39];

		//10round
		s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[40];
		s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[41];
		s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[42];
		s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[43];

		//11round
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[44];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[45];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[46];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[47];

		//12round
		s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >> 8) & 0xff] ^ Te3[t3 & 0xff] ^ W[48];
		s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >> 8) & 0xff] ^ Te3[t0 & 0xff] ^ W[49];
		s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >> 8) & 0xff] ^ Te3[t1 & 0xff] ^ W[50];
		s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >> 8) & 0xff] ^ Te3[t2 & 0xff] ^ W[51];


		//13round
		t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >> 8) & 0xff] ^ Te3[s3 & 0xff] ^ W[52];
		t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >> 8) & 0xff] ^ Te3[s0 & 0xff] ^ W[53];
		t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >> 8) & 0xff] ^ Te3[s1 & 0xff] ^ W[54];
		t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >> 8) & 0xff] ^ Te3[s2 & 0xff] ^ W[55];

		//14round
		s0 = (Te2[t0 >> 24] & 0xff000000) ^ (Te3[(t1 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t2 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t3 & 0xff] & 0x000000ff) ^ W[56];
		s1 = (Te2[t1 >> 24] & 0xff000000) ^ (Te3[(t2 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t3 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t0 & 0xff] & 0x000000ff) ^ W[57];
		s2 = (Te2[t2 >> 24] & 0xff000000) ^ (Te3[(t3 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t0 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t1 & 0xff] & 0x000000ff) ^ W[58];
		s3 = (Te2[t3 >> 24] & 0xff000000) ^ (Te3[(t0 >> 16) & 0xff] & 0x00ff0000) ^ (Te0[(t1 >> 8) & 0xff] & 0x0000ff00) ^ (Te1[t2 & 0xff] & 0x000000ff) ^ W[59];

	}

	u4byte_out(CT, s0);
	u4byte_out(CT + 4, s1);
	u4byte_out(CT + 8, s2);
	u4byte_out(CT + 12, s3);
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


void RoundKeyGeneration128_Optimaization(u8 MK[], u32 W[]) {
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
}




void AES_keySchedule(u8 MK[], u8 RK[], int keysize) {
	if (keysize == 128) RoundKeyGeneration128(MK, RK);
	//if (keysize == 192) RoundKeyGeneration192(MK, RK);
	//if (keysize == 256) RoundKeyGeneration256(MK, RK);


}

void AES_keySchedule_Optimization(u8 MK[], u32 W[], int keysize) {
	if (keysize == 128) RoundKeyGeneration128_Optimaization(MK, W);
	//if (keysize == 192) RoundKeyGeneration192(MK, W);
	//if (keysize == 256) RoundKeyGeneration256(MK, W);


}



int main() {
	int i;
	//u8 PT[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	u8 PT[16] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a }; //평문
	//u8 MK[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
	u8 MK[16] = { 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; //master key
	u8 CT[16] = { 0x00, }; // 암호문
	u8 RK[240] = { 0x00, }; //round key
	u32 W[60] = { 0x00, };
	int keysize = 128;
	u8 temp;
	clock_t start, finish;


	



	
	AES_keySchedule(MK, RK, keysize); //1round : RK 0~15, 2round : 16~31   마스터키로부터 라운드키를 순차적으로 담는 함수
	start = clock();
	AES_ENC(PT, RK, CT, keysize);
	finish = clock();
	printf("AES : \n");
	for (i = 0; i < 16; i++) {
		printf("%02x ", CT[i]);
	}

	printf("\n");
	printf("computation time : %f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
	printf("\n\n");



	AES_keySchedule_Optimization(MK, W, keysize); //1round : RK 0~15, 2round : 16~31   마스터키로부터 라운드키를 순차적으로 담는 함수
	start = clock();

	AES_ENC_Optimization(PT, W, CT, keysize);


	finish = clock();
	printf("AES Optimization : \n");
	for (i = 0; i < 16; i++) {
		printf("%02x ", CT[i]);
	}
	printf("\n");
	printf("computation time : %f seconds\n", (double)(finish - start) / CLOCKS_PER_SEC);
	



	/*
	//Te0 생성
	printf("u32 Te0[256] = {\n");
	for (i = 0; i < 256; i++) {
		temp = Sbox[i];
		printf("0x%02x%02x%02x%02x, ", (u8)MUL2(temp), temp, temp, (u8)MUL3(temp)); //2 1 1 3
		if (i % 8 == 7)
			printf("\n");
	}
	*/

	


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