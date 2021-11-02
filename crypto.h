#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>

typedef struct _Crypto {
	EVP_CIPHER_CTX *ctx;
} Crypto;

Crypto *crypto_new();
int crypto_set_key(Crypto *crypto, char *key, char *iv);
int crypto_encrypt(Crypto *crypto, void *dst, void *src, int length);
int crypto_decrypt(Crypto *crypto, void *dst, void *src, int length);
void crypto_free(Crypto *crypto);

#endif