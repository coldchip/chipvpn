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

void chipvpn_event_loop(ChipVPNConfig *config);
void chipvpn_socket_event(ChipVPNConfig *config, VPNPeer *peer, VPNPacket *packet);

void chipvpn_service(ChipVPNConfig *config);
void chipvpn_set_key_event(ChipVPNConfig *config, VPNPeer *peer, VPNKeyPacket *packet);
void chipvpn_auth_event(ChipVPNConfig *config, VPNPeer *peer, VPNAuthPacket *packet);
void chipvpn_assign_event(ChipVPNConfig *config, VPNPeer *peer, VPNAssignPacket *packet);
void chipvpn_data_event(ChipVPNConfig *config, VPNPeer *peer, VPNDataPacket *packet, int size);
void chipvpn_ping_event(ChipVPNConfig *config, VPNPeer *peer);
void chipvpn_pong_event(ChipVPNConfig *config, VPNPeer *peer);

void chipvpn_tun_event(ChipVPNConfig *config, VPNDataPacket *packet, int size);
void chipvpn_disconnect_peer(ChipVPNConfig *config, VPNPeer *peer);
void chipvpn_exit(int type);

#endif