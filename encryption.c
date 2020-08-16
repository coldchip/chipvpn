#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "chipvpn.h"
#include "aes.h"

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