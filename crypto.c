#include "crypto.h"
#include "peer.h"
#include "rc4.h"
#include <string.h>

void chipvpn_encrypt_buf(VPNPeer *peer, char *data, int length) {
	rc4_crypt(peer->outbound_rc4, (uint8_t*)data, length);
	
	int i;
	for(i = 0; i < length; i++) {
		data[i] ^= 54;
	}
}

void chipvpn_decrypt_buf(VPNPeer *peer, char *data, int length) {
	int i;
	for(i = 0; i < length; i++) {
		data[i] ^= 54;
	}

	rc4_crypt(peer->inbound_rc4, (uint8_t*)data, length);
}