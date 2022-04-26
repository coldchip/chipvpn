#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <stdbool.h>

typedef struct _VPNCrypto {
	EVP_CIPHER_CTX *ctx;
} VPNCrypto;

VPNCrypto     *chipvpn_crypto_create();
bool           chipvpn_crypto_set_key(VPNCrypto *crypto, uint8_t *key, uint8_t *iv);
bool           chipvpn_crypto_encrypt(VPNCrypto *crypto, void *dst, void *src, int length);
bool           chipvpn_crypto_decrypt(VPNCrypto *crypto, void *dst, void *src, int length);
void           chipvpn_crypto_free(VPNCrypto *crypto);

#endif