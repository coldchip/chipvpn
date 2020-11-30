#include "chipvpn.h"

void encrypt(char *key, char *data, int length) {
	int i;
	for(i = 0; i < length; i++) {
		*(data + i) ^= *(key + (i % 64));
	}
}

void decrypt(char *key, char *data, int length) {
	int i;
	for(i = 0; i < length; i++) {
		*(data + i) ^= *(key + (i % 64));
	}
}