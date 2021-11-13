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

void chipvpn_socket_event(VPNPeer *peer, VPNPacket *packet);

void chipvpn_service();
void chipvpn_set_key_event(VPNPeer *peer, VPNKeyPacket *packet);
void chipvpn_auth_event(VPNPeer *peer, VPNAuthPacket *packet);
void chipvpn_assign_event(VPNPeer *peer, VPNAssignPacket *packet);
void chipvpn_data_event(VPNPeer *peer, VPNDataPacket *packet, int size);
void chipvpn_ping_event(VPNPeer *peer);
void chipvpn_pong_event(VPNPeer *peer);

void chipvpn_tun_event(VPNDataPacket *packet, int size);
void chipvpn_disconnect_peer(VPNPeer *peer);
void chipvpn_exit(int type);

#endif