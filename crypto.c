#include "crypto.h"
#include "peer.h"
#include "aes.h"

char iv[] = {
	0x2e, 0xa5, 0xb3, 0x17, 0x57, 0x11, 0xa6, 0x65, 
	0x33, 0x49, 0x7f, 0x76, 0x7f, 0x7f, 0x15, 0x9b 
};

void chipvpn_encrypt_buf(VPNPeer *peer, char *data, int length) {
	AES_ctx_set_iv(&peer->ctx, (uint8_t*)&iv);
	AES_CTR_xcrypt_buffer(&peer->ctx, (uint8_t*)data, length);
}

void chipvpn_decrypt_buf(VPNPeer *peer, char *data, int length) {
	AES_ctx_set_iv(&peer->ctx, (uint8_t*)&iv);
	AES_CTR_xcrypt_buffer(&peer->ctx, (uint8_t*)data, length);
}