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

typedef struct GUI_ {
	uint64_t tx;
	uint64_t rx;
	char ip[20];
	uint16_t port;
} GUI;

typedef enum {
	STATUS_CONNECTING,
	STATUS_CONNECTED,
	STATUS_DISCONNECTING,
	STATUS_DISCONNECTED
} ChipVPNStatus;

void chipvpn_event_loop(ChipVPNConfig *config, void (*status)(ChipVPNStatus));
void chipvpn_socket_event(ChipVPNConfig *config, VPNPeer *peer, VPNPacket *packet, void (*status)(ChipVPNStatus));
void chipvpn_tun_event(ChipVPNConfig *config, VPNDataPacket *packet, int size, void (*status)(ChipVPNStatus));
void chipvpn_disconnect_peer(ChipVPNConfig *config, VPNPeer *peer);
void chipvpn_gui_event(GUI *gui);
void chipvpn_cleanup_event(int type);

#endif