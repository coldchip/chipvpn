/*
 * ColdChip ChipVPN
 *
 * Copyright (c) 2016-2021, Ryan Loh <ryan@coldchip.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README for more details.
 */

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