#ifndef CRYPTO
#define CRYPTO

#include "peer.h"

void chipvpn_encrypt_buf(VPNPeer *peer, char *data, int length);
void chipvpn_decrypt_buf(VPNPeer *peer, char *data, int length);

#endif