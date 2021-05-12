#include "chipvpn.h"

void chip_randomize_keys(ChipKey *key) {
	//syscall(SYS_getrandom, key->key, sizeof(key->key), 1);
}

void chip_encrypt_buf(char *data, int length, ChipKey *key) {
	for(int i = 0; i < length; i++) {
		data[i] ^= key->key[i % sizeof(key->key)];
	}
}

void chip_decrypt_buf(char *data, int length, ChipKey *key) {
	for(int i = 0; i < length; i++) {
		data[i] ^= key->key[i % sizeof(key->key)];
	}
}

