#ifndef HASHE9
#define HASHE9

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

const int hashE9Len = 32;
const int hashE9LenHex = hashE9Len*2 + 1;

static int byteToDec(char* byte) {
	int a = byte[0] << 24 | byte[1] << 16 | byte[2] << 8 | byte[3];
	return a;
}

static void decToBytes(int32_t* a, char* byte) {
	byte[0] = *a >> 24;
	byte[1] = *a >> 16;
	byte[2] = *a >> 8;
	byte[3] = *a;
}

// MALLOC BIG DATA

void hashE9(const char* data, const int len, char* output) {
	for (int i = 0; i<hashE9Len; ++i) { // base init
		output[i] = (data[i%len] + data[(i+1)%len]) ^ 0xE8;
	}
	for (int i = 0; i<len; ++i) {
		output[i] ^= data[i%len];
	}
	for (int c = 0; c<hashE9Len; c += 4) {
		int32_t a = byteToDec(output+c);
		int32_t b = byteToDec(output+((c+1)%(hashE9Len-4)));
		a ^= ((a + b) * 0xf8be2937) ^ ((a-b-b) * 0x8eff926b);
		decToBytes(&a, output+c);
	}
	int x = 1048576 * 4; // x * 1 Mb
	char* pool = (char*)malloc(x);
	if (pool == NULL) {
		printf("Not enough RAM for hash()\n");
		return;
	}
	for (int z = 0; z<x; ++z) {
		pool[z] = output[z%hashE9Len];
	}
	for (int i = 0; i<x; i += 4) {
		pool[i] = data[i%len] ^ output[i%hashE9Len] ^ pool[i] ^ pool[i+1] ^ pool[i+2] ^ pool[i+3];
		int32_t a = byteToDec(pool+i);
		int32_t b = byteToDec((char*)(data+abs(i%len-4)));
		int ind = abs(((0x7620e1fa * (pool[i] * output[i%hashE9Len])) ^ a) % x);
		a &= (pool[ind] ^ pool[ind+1] ^ pool[ind+2] ^ pool[ind+3] ^ (output[i%hashE9Len]+1)) * 0x7620e1fa + 0x4012313e + (i*b);
		if (pool[i] > 100) {
			a += 300;
		} else if (pool[i] > 200) {
			a -= 0x457cb38a;
		} else {
			a *= 37;
		}
		decToBytes(&a, pool+i);
		pool[abs(a)%x] ^= pool[i] * -a * pool[i%x];
	}
	for (int i = 0; i<x; ++i) {
		int ind = abs(0x72e1abcc * i ^ pool[i]);
		output[i%hashE9Len] ^= pool[i] ^ pool[ind%x];
	}
	free(pool);
}

void hashE9Hex(const char* data, const int len, char* output) {
	unsigned char hash[hashE9Len];
	hashE9(data, len, hash);
	for (int i = 0; i<hashE9Len; ++i) {
		sprintf(output+(i*2), "%02x", (unsigned char)hash[i]);
	}
}

/*int main() {
	char hash[hashE9LenHex];
	hashE9Hex("anal17", 6, hash);
	printf("%s\n", hash);
}*/

#endif