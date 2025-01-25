#include<stdio.h>
#include<assert.h>
#include<stdlib.h>
#include "AES.h"

#define MUL2(a) (a << 1)^(a & 0x80 ? 0x1b : 0x00) //x �� ���ϴ� �κ� => 0x02
#define MUL3(a) (MUL2(a))^(a) // 3 �� ���ϴ� �κ�
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


void MixColumns(u8 S[16]) { // state �� ���� ����
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


void SubBytes(u8 S[16]) { // 16 bytes �Է� ������ ���Է� Sbox_inverse ��ġ �ؼ� ���
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

void ShiftRows(u8 S[16]) { // 16 bytes shift �� ��
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

void AddRoundKey(u8 S[16], u8 RK[16]) { // 16byte �Է� ������ �ΰ��� xor �ؼ� temp �� ��´�
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

void XOR16Bytes(u8 S[16], u8 RK[16]) { // S = S xor RK
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

void AES_DEC(u8 CT[16], u8 RK[], u8 PT[16], int keysize) {
	int Nr = keysize / 32 + 6; // ����� ���
	int i;
	u8 temp[16];

	for (i = 0; i < 16; i++) {
		temp[i] = CT[i];
	}

	AddRoundKey(temp, RK + 16 * (Nr)); // temp�� 16byte �� RK�� ù 16byte�� xor �Ͽ� temp �� ����� ��� �Լ� , 0 ����
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

void CBC_Decryption(char* inputfile, char* outputfile, u8 W[]) {
	FILE* rfp, * wfp;
	u8* inputbuf, * outputbuf;
	u8 IV[16] = { 0x00, };
	u32 DataLen, i;

	fopen_s(&rfp, inputfile, "rb");
	if (rfp == NULL) {
		perror("fopen_s 실패\n");
		return;
	}
	fseek(rfp, 0, SEEK_END);
	DataLen = ftell(rfp);
	fseek(rfp, 0, SEEK_SET);

	inputbuf = calloc(DataLen, sizeof(u8));
	outputbuf = calloc(DataLen, sizeof(u8));
	if (inputbuf == NULL || outputbuf == NULL) {
		perror("메모리 할당 실패\n");
		fclose(rfp);
		return;
	}

	fread(inputbuf, 1, DataLen, rfp);
	fclose(rfp);

	// 첫 번째 블록 복호화
	AES_DEC(inputbuf, W, outputbuf, 128);
	XOR16Bytes(outputbuf, IV);

	// 나머지 블록 복호화
	for (i = 1; i < DataLen / 16; i++) {
		AES_DEC(inputbuf + 16 * i, W, outputbuf + 16 * i, 128);
		XOR16Bytes(outputbuf + 16 * i, inputbuf + 16 * (i - 1));
	}

	// 패딩 제거
	u8 padding_value = outputbuf[DataLen - 1];
	if (padding_value > 0 && padding_value <= 16) {
		for (i = 0; i < padding_value; i++) {
			if (outputbuf[DataLen - 1 - i] != padding_value) {
				perror("잘못된 패딩\n");
				free(inputbuf);
				free(outputbuf);
				return;
			}
		}
		DataLen -= padding_value;
	}
	else {
		fprintf(stderr, "잘못된 패딩 값\n");
		free(inputbuf);
		free(outputbuf);
		return;
	}

	fopen_s(&wfp, outputfile, "wb");
	if (wfp == NULL) {
		perror("fopen_s 실패\n");
		free(inputbuf);
		free(outputbuf);
		return;
	}

	fwrite(outputbuf, 1, DataLen, wfp);
	fclose(wfp);

	free(inputbuf);
	free(outputbuf);
}





int main(int argc, char* argv[]) {
	//u8 PT[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
	u8 PT[16] = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a }; //평문
	//u8 MK[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
	u8 MK[16] = { 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c }; //master key
	u8 CT[16] = { 0x00, }; // 암호문
	u8 RK[240] = { 0x00, }; //round key
	u8 W[240] = { 0x00, };
	int keysize = 128;


	if (strcmp(argv[1], "ecb") == 0) {
		return;
	}
	else if (strcmp(argv[1], "cbc") == 0) {
		AES_keySchedule(MK, W, keysize);
		CBC_Decryption(argv[2], argv[3], W);
	}
	return 0;
}