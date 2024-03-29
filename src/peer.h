/*
 * ColdChip ChipVPN
 *
 * Copyright (c) 2016-2021, Ryan Loh <ryan@chip.sg>
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
#include "bucket.h"
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

typedef enum {
	PEER_STATE_INIT,
	PEER_STATE_KEY,
	PEER_STATE_LOGIN,
	PEER_STATE_CONNECTED
} PeerState;

typedef struct _VPNPeer {
	ListNode node;
	int fd;
	struct sockaddr_in addr;

	PeerState state;

	bool is_init;
	bool inbound_encrypted;
	bool outbound_encrypted;
	bool is_authed;
	bool is_ip_set;
	bool has_route_set;

	uint32_t last_ping;

	struct in_addr internal_ip;

	uint64_t tx;
	uint64_t rx;
	uint64_t last_tx;
	uint64_t last_rx;
	uint64_t tx_max;
	uint64_t rx_max;

	List routes;

	List inbound_firewall;
	List outbound_firewall;

	// stage 1(encrypted buffer)
	VPNBucket *sock_inbound;
	VPNBucket *sock_outbound;
	
	// stage 2(decrypted buffer)
	VPNBucket *vpn_inbound;
	VPNBucket *vpn_outbound;

	VPNCrypto *inbound_cipher;
	VPNCrypto *outbound_cipher;
} VPNPeer;

VPNPeer           *chipvpn_peer_create(int fd);
void               chipvpn_peer_free(VPNPeer *peer);
void               chipvpn_peer_disconnect(VPNPeer *peer);

int                chipvpn_peer_socket_inbound(VPNPeer *peer);
int                chipvpn_peer_socket_outbound(VPNPeer *peer);

int                chipvpn_peer_cipher_inbound(VPNPeer *peer);
int                chipvpn_peer_cipher_outbound(VPNPeer *peer);

int                chipvpn_peer_recv(VPNPeer *peer, VPNPacket *dst);
int                chipvpn_peer_send(VPNPeer *peer, VPNPacketType type, void *data, uint16_t size, VPNPacketFlag flag);

bool               chipvpn_peer_get_free_ip(List *peers, struct in_addr gateway, struct in_addr *assign);
VPNPeer           *chipvpn_peer_get_by_ip(List *peers, struct in_addr ip);

#endif