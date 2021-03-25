#include "chipsock.h"

void chip_encrypt_buf(char *data, int length) {
	uint8_t key[16] = {
		0x43, 0x37, 0x74, 0x3f, 0x0b, 0x33, 0x4e, 0x9c, 
		0x7a, 0x5d, 0x26, 0x9a, 0x8d, 0xd2, 0x7b, 0x9d
	};
	for(int i = 0; i < length; i++) {
		key[i % sizeof(key)] ^= (i | key[i % sizeof(key)]);
		key[i % sizeof(key)] += 1;
		*(data + i) ^= (key[(i + 0) % sizeof(key)] ^ (i));
		*(data + i) ^= (key[(i + 1) % sizeof(key)] | 0x7F);
	}
}

void chip_decrypt_buf(char *data, int length) {
	uint8_t key[16] = {
		0x43, 0x37, 0x74, 0x3f, 0x0b, 0x33, 0x4e, 0x9c, 
		0x7a, 0x5d, 0x26, 0x9a, 0x8d, 0xd2, 0x7b, 0x9d
	};
	for(int i = 0; i < length; i++) {
		key[i % sizeof(key)] ^= (i | key[i % sizeof(key)]);
		key[i % sizeof(key)] += 1;
		*(data + i) ^= (key[(i + 0) % sizeof(key)] ^ (i));
		*(data + i) ^= (key[(i + 1) % sizeof(key)] | 0x7F);
	}
}

