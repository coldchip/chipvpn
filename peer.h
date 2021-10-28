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

#ifndef PEER_H
#define PEER_H

#include "list.h"
#include "packet.h"
#include "rc4.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct _VPNPacketQueue {
	ListNode node;
	int rw_offset;
	VPNPacket packet;
} VPNPacketQueue;

typedef struct _VPNPeer {
	ListNode node;
	int fd;
	bool is_authed;
	uint32_t last_ping;
	uint32_t internal_ip;

	uint64_t tx;
	uint64_t rx;

	uint32_t inbound_buffer_pos;
	char inbound_buffer[sizeof(VPNPacket)];
	List inbound_queue;

	uint32_t outbound_buffer_pos;
	char outbound_buffer[sizeof(VPNPacket)];
	List outbound_queue;

	rc4_state_t *inbound_rc4;
	rc4_state_t *outbound_rc4;
} VPNPeer;

VPNPeer           *chipvpn_peer_alloc(int fd);
void               chipvpn_peer_dealloc(VPNPeer *peer);
void               chipvpn_set_crypto(VPNPeer *peer, char *key);
int                chipvpn_peer_dispatch_inbound(VPNPeer *peer);
int                chipvpn_peer_dispatch_outbound(VPNPeer *peer);
int                chipvpn_peer_recv_nio(VPNPeer *peer, VPNPacket *dst);
int                chipvpn_peer_send_nio(VPNPeer *peer, VPNPacketType type, void *data, int size);
int                chipvpn_peer_raw_recv(VPNPeer *peer, void *buf, int size, int *err);
int                chipvpn_peer_raw_send(VPNPeer *peer, void *buf, int size, int *err);
uint32_t           chipvpn_get_peer_free_ip(List *peers, char *gateway);
VPNPeer           *chipvpn_get_peer_by_ip(List *peers, uint32_t ip);

#endif