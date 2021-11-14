#include <openssl/evp.h>
#include <openssl/aes.h>
#include <stdbool.h>
#include "crypto.h"

Crypto *crypto_new() {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx) {
		return NULL;
	}
	Crypto *crypto = malloc(sizeof(Crypto));
	crypto->ctx = ctx;
	return crypto;
}

bool crypto_set_key(Crypto *crypto, char *key, char *iv) {
	return EVP_CipherInit(crypto->ctx, EVP_aes_256_ctr(), (unsigned char*)key, (unsigned char*)iv, 0);
}

bool crypto_encrypt(Crypto *crypto, void *dst, void *src, int length) {
	int i;
	if(!EVP_CipherUpdate(crypto->ctx, (unsigned char*)dst, &i, (unsigned char*)src, length)) {
		return false;
	}
	if(!EVP_CipherFinal_ex(crypto->ctx, (unsigned char*)dst + i, &i)) {
		return false;
	}
	return true;
}

bool crypto_decrypt(Crypto *crypto, void *dst, void *src, int length) {
	int i;
	if(!EVP_CipherUpdate(crypto->ctx, (unsigned char*)dst, &i, (unsigned char*)src, length)) {
		return false;
	}
	if(!EVP_CipherFinal_ex(crypto->ctx, (unsigned char*)dst + i, &i)) {
		return false;
	}
	return true;
}

void crypto_free(Crypto *crypto) {
	EVP_CIPHER_CTX_free(crypto->ctx);
	free(crypto);
}