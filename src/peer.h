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
#include "crypto.h"
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

typedef struct _VPNPeer {
	ListNode node;
	int fd;
	int id;
	bool encrypted;
	struct sockaddr_in addr;
	bool is_authed;
	uint32_t last_ping;
	struct in_addr internal_ip;

	uint64_t tx;
	uint64_t rx;
	uint64_t tx_max;
	uint64_t rx_max;

	List inbound_firewall;
	List outbound_firewall;

	uint32_t inbound_buffer_pos;
	uint32_t outbound_buffer_pos;
	
	VPNPacket inbound_buffer;
	VPNPacket outbound_buffer;

	VPNCrypto *inbound_aes;
	VPNCrypto *outbound_aes;
} VPNPeer;

VPNPeer           *chipvpn_peer_new(int fd);
void               chipvpn_peer_free(VPNPeer *peer);
void               chipvpn_peer_disconnect(VPNPeer *peer);
void               chipvpn_peer_set_key(VPNPeer *peer, uint8_t *key);
void               chipvpn_peer_set_encryption(VPNPeer *peer, bool encrypted);
bool               chipvpn_peer_get_encryption(VPNPeer *peer);
bool               chipvpn_peer_get_login(VPNPeer *peer);
void               chipvpn_peer_set_login(VPNPeer *peer, bool login);
bool               chipvpn_peer_readable(VPNPeer *peer);
bool               chipvpn_peer_writeable(VPNPeer *peer);
VPNPacketError     chipvpn_peer_dispatch_inbound(VPNPeer *peer);
VPNPacketError     chipvpn_peer_dispatch_outbound(VPNPeer *peer);
bool               chipvpn_peer_recv(VPNPeer *peer, VPNPacket *dst);
bool               chipvpn_peer_send(VPNPeer *peer, VPNPacketType type, void *data, int size);
int                chipvpn_peer_raw_recv(VPNPeer *peer, void *buf, int size, int *err);
int                chipvpn_peer_raw_send(VPNPeer *peer, void *buf, int size, int *err);
bool               chipvpn_peer_get_free_ip(List *peers, struct in_addr gateway, struct in_addr *assign);
VPNPeer           *chipvpn_peer_get_by_ip(List *peers, struct in_addr ip);

#endif