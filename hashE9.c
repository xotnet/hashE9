#ifndef HASHE9
#define HASHE9

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

const int hashE9Len = 32;
const int hashE9LenHex = hashE9Len*2 + 1;

static char* memptr = NULL;

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
	for (int i = 0; i<x; ++i) {
		pool[i] = 0x2a - output[i%hashE9Len] - i>0 ? pool[i-1] : 99;
	}
	for (int i = 0; i<x; i += 4) {
		// filling an array randomly
		pool[i] = (data[i%len] & output[i%hashE9Len]) ^ pool[i] ^ pool[i+1] ^ pool[i+2] ^ (pool[i+3] & pool[i%x]);
		int32_t a = byteToDec(pool+i);
		int ind = abs(((0x7620e1fa * (pool[i] * output[i%hashE9Len])) ^ a) % (i>0 ? i : 1));
		a &= (pool[ind] ^ pool[ind+1] ^ pool[ind+2] ^ pool[ind+3] ^ (output[i%hashE9Len]+1)) * 0x7620e1fa + 0x4012313e + (i*a*pool[i%x]);
		if (pool[i] > 100) {
			a += 300;
		} else if (pool[i] > 200) {
			a -= 0x457cb38a;
		} else {
			a *= 37;
		}
		decToBytes(&a, pool+i);
		// set random index
		int16_t temp = i!=0 ? (pool[i-1] * 2) / 3 : (pool[i] - pool[i]*11);
		pool[i%x] ^= pool[i] * -a * pool[abs(a % (i>0 ? i : 1))] - temp - (int8_t)tan(pool[i]) - (int8_t)cos(pool[i]);
	}
	for (int i = 0; i<x; ++i) {
		int ind = abs(0x72e1abcc * i ^ pool[i]);
		output[i%hashE9Len] ^= (pool[i] & pool[ind%x]) + pool[i%x];
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
	for (int i = 0; i<24; i++) {
		char toHash[32];
		int len = sprintf(toHash, "AnalBoobs+%d", i);
		hashE9Hex(toHash, len, hash);
		printf("%s\n", hash);
	}
	printf("SUC!\n");
}*/

#endif
