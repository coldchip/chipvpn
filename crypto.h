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

#ifndef CRYPTO
#define CRYPTO

#include "peer.h"

void chipvpn_encrypt_buf(VPNPeer *peer, char *data, int length);
void chipvpn_decrypt_buf(VPNPeer *peer, char *data, int length);

#endif