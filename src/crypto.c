#include <openssl/evp.h>
#include <openssl/aes.h>
#include <stdbool.h>
#include "crypto.h"

VPNCrypto *chipvpn_crypto_new() {
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx) {
		return NULL;
	}
	VPNCrypto *crypto = malloc(sizeof(VPNCrypto));
	crypto->ctx = ctx;
	return crypto;
}

bool chipvpn_crypto_set_key(VPNCrypto *crypto, uint8_t *key, uint8_t *iv) {
	return EVP_CipherInit(crypto->ctx, EVP_aes_256_ctr(), key, iv, 0);
}

bool chipvpn_crypto_encrypt(VPNCrypto *crypto, void *dst, void *src, int length) {
	int i;
	if(!EVP_CipherUpdate(crypto->ctx, (unsigned char*)dst, &i, (unsigned char*)src, length)) {
		return false;
	}
	if(!EVP_CipherFinal_ex(crypto->ctx, (unsigned char*)dst + i, &i)) {
		return false;
	}
	return true;
}

bool chipvpn_crypto_decrypt(VPNCrypto *crypto, void *dst, void *src, int length) {
	int i;
	if(!EVP_CipherUpdate(crypto->ctx, (unsigned char*)dst, &i, (unsigned char*)src, length)) {
		return false;
	}
	if(!EVP_CipherFinal_ex(crypto->ctx, (unsigned char*)dst + i, &i)) {
		return false;
	}
	return true;
}

void chipvpn_crypto_free(VPNCrypto *crypto) {
	EVP_CIPHER_CTX_free(crypto->ctx);
	free(crypto);
}