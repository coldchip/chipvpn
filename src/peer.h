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

typedef struct _VPNPeer {
	ListNode node;
	int fd;
	struct sockaddr_in addr;
	bool is_authed;
	uint32_t last_ping;
	bool has_route_set;
	struct in_addr internal_ip;

	uint64_t tx;
	uint64_t rx;
	uint64_t tx_max;
	uint64_t rx_max;

	List routes;

	List inbound_firewall;
	List outbound_firewall;

	// stage 1(encrypted buffer)
	VPNBucket *enc_inbound;
	VPNBucket *enc_outbound;
	
	// stage 2(decrypted buffer)
	VPNBucket *dec_inbound;
	VPNBucket *dec_outbound;

	VPNCrypto *inbound_aes;
	VPNCrypto *outbound_aes;
} VPNPeer;

VPNPeer           *chipvpn_peer_create(int fd);
void               chipvpn_peer_free(VPNPeer *peer);
void               chipvpn_peer_disconnect(VPNPeer *peer);
void               chipvpn_peer_set_key(VPNPeer *peer, uint8_t *key);
void               chipvpn_peer_set_encryption(VPNPeer *peer, bool encrypted);
bool               chipvpn_peer_get_encryption(VPNPeer *peer);
bool               chipvpn_peer_get_login(VPNPeer *peer);
void               chipvpn_peer_set_login(VPNPeer *peer, bool login);

int                chipvpn_peer_socket_inbound(VPNPeer *peer);
int                chipvpn_peer_socket_outbound(VPNPeer *peer);

int                chipvpn_peer_pipe_inbound(VPNPeer *peer);
int                chipvpn_peer_pipe_outbound(VPNPeer *peer);

int                chipvpn_peer_recv(VPNPeer *peer, VPNPacket *dst);
int                chipvpn_peer_send(VPNPeer *peer, VPNPacketType type, void *data, int size, VPNPacketFlag flag);

bool               chipvpn_peer_get_free_ip(List *peers, struct in_addr gateway, struct in_addr *assign);
VPNPeer           *chipvpn_peer_get_by_ip(List *peers, struct in_addr ip);

#endif