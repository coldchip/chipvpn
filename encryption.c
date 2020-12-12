#include "chipvpn.h"

EncryptCTX *chip_encrypt_init() {
	EncryptCTX *ctx = malloc(sizeof(EncryptCTX));
	return ctx;
}

void chip_encrypt_set_key(EncryptCTX *ctx, char *key) {
	AES_init_ctx(&ctx->aes_ctx, (uint8_t*)key);
}

void chip_encrypt_buf(EncryptCTX *ctx, char *data, int length) {
	uint8_t iv[16] = {
		0x43, 0x37, 0x74, 0x3f, 0x0b, 0x33, 0x4e, 0x9c, 
		0x7a, 0x5d, 0x26, 0x9a, 0x8d, 0xd2, 0x7b, 0x9d
	};
	AES_ctx_set_iv(&ctx->aes_ctx, iv);
	AES_CTR_xcrypt_buffer(&ctx->aes_ctx, (uint8_t*)data, length);
}

void chip_decrypt_buf(EncryptCTX *ctx, char *data, int length) {
	uint8_t iv[16] = {
		0x43, 0x37, 0x74, 0x3f, 0x0b, 0x33, 0x4e, 0x9c, 
		0x7a, 0x5d, 0x26, 0x9a, 0x8d, 0xd2, 0x7b, 0x9d
	};
	AES_ctx_set_iv(&ctx->aes_ctx, iv);
	AES_CTR_xcrypt_buffer(&ctx->aes_ctx, (uint8_t*)data, length);
}

void chip_decrypt_free(EncryptCTX *ctx) {
	free(ctx);
}