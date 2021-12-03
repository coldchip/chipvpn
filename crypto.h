#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <stdbool.h>

typedef struct _Crypto {
	EVP_CIPHER_CTX *ctx;
} Crypto;

Crypto        *crypto_new();
bool           crypto_set_key(Crypto *crypto, uint8_t *key, uint8_t *iv);
bool           crypto_encrypt(Crypto *crypto, void *dst, void *src, int length);
bool           crypto_decrypt(Crypto *crypto, void *dst, void *src, int length);
void           crypto_free(Crypto *crypto);

#endif