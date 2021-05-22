#include "crypto.h"

char key[] = {
	0x2e, 0xa5, 0xb3, 0x17, 0x57, 0x11, 0xa6, 0x65, 
	0x33, 0x49, 0x7f, 0x76, 0x7f, 0x7f, 0x15, 0x9b 
};

void chipvpn_encrypt_buf(char *data, int length) {
	for(int i = 0; i < length; i++) {
		data[i] ^= key[i % sizeof(key)];
	}
}

void chipvpn_decrypt_buf(char *data, int length) {
	for(int i = 0; i < length; i++) {
		data[i] ^= key[i % sizeof(key)];
	}
}