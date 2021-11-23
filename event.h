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

#ifndef EVENT_H
#define EVENT_H

#include "peer.h"
#include "packet.h"
#include "config.h"
#include <stdint.h>

#ifndef MAX
#define MAX(a,b) \
({ __typeof__ (a) _a = (a); \
__typeof__ (b) _b = (b); \
_a > _b ? _a : _b; })
#endif

void chipvpn_init(ChipVPNConfig *config);
void chipvpn_setup();
void chipvpn_loop();
void chipvpn_cleanup();

void chipvpn_ticker();

bool chipvpn_socket_event(VPNPeer *peer, VPNPacket *packet);

bool chipvpn_send_key(VPNPeer *peer);
bool chipvpn_recv_key(VPNPeer *peer, VPNKeyPacket *packet, int size);

bool chipvpn_send_auth(VPNPeer *peer);
bool chipvpn_recv_auth(VPNPeer *peer, VPNAuthPacket *packet, int size);

bool chipvpn_send_assign(VPNPeer *peer);
bool chipvpn_recv_assign(VPNPeer *peer, VPNAssignPacket *packet, int size);

bool chipvpn_send_data(VPNDataPacket *packet, int size);
bool chipvpn_recv_data(VPNPeer *peer, VPNDataPacket *packet, int size);

bool chipvpn_ping_event(VPNPeer *peer);
bool chipvpn_pong_event(VPNPeer *peer);

void chipvpn_disconnect_peer(VPNPeer *peer);
void chipvpn_exit(int type);

#endif