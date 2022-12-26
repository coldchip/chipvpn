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

#include "peer.h"
#include "packet.h"
#include "chipvpn.h"
#include "crypto.h"
#include "firewall.h"
#include "route.h"
#include "bucket.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

VPNPeer *chipvpn_peer_create(int fd) {
	VPNPeer *peer             = malloc(sizeof(VPNPeer));
	peer->fd                  = fd;
	peer->is_authed           = false;
	peer->tx                  = 0;
	peer->rx                  = 0;
	peer->tx_max              = 0xFFFFFFFFFFFFFFFF;
	peer->rx_max              = 0xFFFFFFFFFFFFFFFF;
	peer->last_ping           = chipvpn_get_time();
	peer->has_route_set       = false;

	list_clear(&peer->routes);

	list_clear(&peer->inbound_firewall);
	list_clear(&peer->outbound_firewall);

	peer->enc_inbound = chipvpn_bucket_create();
	peer->enc_outbound = chipvpn_bucket_create();

	peer->dec_inbound = chipvpn_bucket_create();
	peer->dec_outbound = chipvpn_bucket_create();

	// Allow all inbound/outbound traffic on peer
	if(!chipvpn_firewall_add_rule(&peer->outbound_firewall, "0.0.0.0/0", RULE_ALLOW)) {
		chipvpn_error("unable to add firewall rule");
	}
	if(!chipvpn_firewall_add_rule(&peer->inbound_firewall, "0.0.0.0/0", RULE_ALLOW)) {
		chipvpn_error("unable to add firewall rule");
	}

	chipvpn_peer_set_login(peer, false);

	peer->inbound_aes = chipvpn_crypto_create();
	if(!peer->inbound_aes) {
		chipvpn_error("unable to set aes ctx for peer");
	}

	peer->outbound_aes = chipvpn_crypto_create();
	if(!peer->outbound_aes) {
		chipvpn_error("unable to set aes ctx for peer");
	}

	uint8_t key[] = { 
		0xc2, 0x06, 0xa0, 0x78, 0x2d, 0x6c, 0x61, 0x17, 
		0x9f, 0x97, 0x03, 0xec, 0xd5, 0x3f, 0xa1, 0xf6
	};

	chipvpn_peer_set_key(peer, key);

	chipvpn_log("peer connected");
	return peer;
}

void chipvpn_peer_free(VPNPeer *peer) {
	chipvpn_peer_set_login(peer, false);

	// routes cleanup
	while(!list_empty(&peer->routes)) {
		VPNRoute *route = (VPNRoute*)list_remove(list_begin(&peer->routes));
		chipvpn_route_free(route);
	}

	// firewall rules cleanup
	while(!list_empty(&peer->inbound_firewall)) {
		VPNRule *rule = (VPNRule*)list_remove(list_begin(&peer->inbound_firewall));
		chipvpn_firewall_free_rule(rule);
	}

	// firewall rules cleanup
	while(!list_empty(&peer->outbound_firewall)) {
		VPNRule *rule = (VPNRule*)list_remove(list_begin(&peer->outbound_firewall));
		chipvpn_firewall_free_rule(rule);
	}

	chipvpn_bucket_free(peer->enc_inbound);
	chipvpn_bucket_free(peer->enc_outbound);

	chipvpn_bucket_free(peer->dec_inbound);
	chipvpn_bucket_free(peer->dec_outbound);

	chipvpn_crypto_free(peer->inbound_aes);
	chipvpn_crypto_free(peer->outbound_aes);
	free(peer);
}

void chipvpn_peer_disconnect(VPNPeer *peer) {
	chipvpn_log("peer disconnected");
	list_remove(&peer->node);
	close(peer->fd);
	chipvpn_peer_free(peer);
}

void chipvpn_peer_set_key(VPNPeer *peer, uint8_t *key) {
	uint8_t iv[] = { 
		0x8e, 0xa2, 0x98, 0x96, 0xc2, 0x37, 0xe8, 0x6e, 
		0x40, 0x7a, 0x74, 0x57, 0x68, 0x72, 0x1b, 0xa9 
	};

	chipvpn_crypto_set_key(peer->inbound_aes, key, iv);
	chipvpn_crypto_set_key(peer->outbound_aes, key, iv);
}

void chipvpn_peer_set_login(VPNPeer *peer, bool login) {
	peer->is_authed = login;
}

bool chipvpn_peer_get_login(VPNPeer *peer) {
	return peer->is_authed;
}

int chipvpn_peer_socket_inbound(VPNPeer *peer) {
	int size = chipvpn_bucket_write_available(peer->enc_inbound);

	if(size) {
		char buf[size];
		int r = recv(peer->fd, buf, size, 0);
		if(r <= 0) {
			if(errno == EAGAIN || errno == EWOULDBLOCK) {
				return VPN_EAGAIN;
			}
			return VPN_CONNECTION_END;
		}

		chipvpn_bucket_write(peer->enc_inbound, buf, r);

		return r;
	}
	return VPN_EAGAIN;
}

int chipvpn_peer_socket_outbound(VPNPeer *peer) {
	int size = chipvpn_bucket_read_available(peer->enc_outbound);

	if(size > 0) {
		int w = send(peer->fd, chipvpn_bucket_get_buffer(peer->enc_outbound), size, 0);
		if(w <= 0) {
			if(errno == EAGAIN || errno == EWOULDBLOCK) {
				return VPN_EAGAIN;
			}
			return VPN_CONNECTION_END;
		}

		return chipvpn_bucket_consume(peer->enc_outbound, w);
	}
	return VPN_EAGAIN;
}

int chipvpn_peer_pipe_inbound(VPNPeer *peer) {
	VPNBucket *src = peer->enc_inbound;
	VPNBucket *dst = peer->dec_inbound;

	if(chipvpn_bucket_read_available(src) > 0 && chipvpn_bucket_write_available(dst) > 0) {
		int size = MIN(chipvpn_bucket_read_available(src), chipvpn_bucket_write_available(dst));

		char src_buf[size], dst_buf[size];
		int r = chipvpn_bucket_read(src, src_buf, size);
		
		if(!chipvpn_crypto_encrypt(peer->inbound_aes, dst_buf, src_buf, r)) {
			return VPN_CONNECTION_END;
		}

		return chipvpn_bucket_write(dst, dst_buf, r);
	}
	return VPN_EAGAIN;
}

int chipvpn_peer_pipe_outbound(VPNPeer *peer) {
	VPNBucket *src = peer->dec_outbound;
	VPNBucket *dst = peer->enc_outbound;

	if(chipvpn_bucket_read_available(src) > 0 && chipvpn_bucket_write_available(dst) > 0) {
		int size = MIN(chipvpn_bucket_read_available(src), chipvpn_bucket_write_available(dst));

		char src_buf[size], dst_buf[size];
		int r = chipvpn_bucket_read(src, src_buf, size);

		if(!chipvpn_crypto_encrypt(peer->outbound_aes, dst_buf, src_buf, r)) {
			return VPN_CONNECTION_END;
		}

		return chipvpn_bucket_write(dst, dst_buf, r);
	}
	return VPN_EAGAIN;
}

bool chipvpn_peer_recv(VPNPeer *peer, VPNPacket *dst) {
	if(chipvpn_bucket_read_available(peer->dec_inbound) >= sizeof(VPNPacketHeader)) {
		VPNPacket *packet = (VPNPacket*)chipvpn_bucket_get_buffer(peer->dec_inbound);

		int size = sizeof(VPNPacketHeader) + PLEN(packet);

		if(chipvpn_bucket_read_available(peer->dec_inbound) >= size) {
			chipvpn_bucket_read(peer->dec_inbound, dst, size);
			return true;
		}
	}
	return false;
}

bool chipvpn_peer_send(VPNPeer *peer, VPNPacketType type, void *data, int size, VPNPacketFlag flag) {
	if(
		(
			flag == VPN_FLAG_DATA && 
			chipvpn_bucket_write_available(peer->dec_outbound) >= sizeof(VPNPacketHeader) + size
		)
		||
		(
			flag == VPN_FLAG_CONTROL
		)
	) {
		VPNPacket packet;
		packet.header.size = htonl(size);
		packet.header.type = (uint8_t)(type & 0xFF);
		if(data && size > 0) {
			memcpy(&packet.data, data, size);
		}

		chipvpn_bucket_write(peer->dec_outbound, &packet, sizeof(VPNPacketHeader) + size);

		return true;
	}
	return false;
}

bool chipvpn_peer_get_free_ip(List *peers, struct in_addr gateway, struct in_addr *assign) {
	// Seems dirty. Please fix
	uint32_t start = gateway.s_addr + (1   << 24);
	uint32_t end   = gateway.s_addr + (200 << 24);
	bool     trip  = false;

	for(uint32_t ip = ntohl(start); ip < ntohl(end); ip++) {
		trip = false;
		for(ListNode *i = list_begin(peers); i != list_end(peers); i = list_next(i)) {
			VPNPeer *peer = (VPNPeer*)i;
			if((peer->internal_ip.s_addr == htonl(ip))) {
				trip = true;
			}
		}
		if(trip == false) {
			assign->s_addr = htonl(ip);
			return true;
		}
	}

	return false;
}

VPNPeer *chipvpn_peer_get_by_ip(List *peers, struct in_addr ip) {
	for(ListNode *i = list_begin(peers); i != list_end(peers); i = list_next(i)) {
		VPNPeer *peer = (VPNPeer*)i;
		if(peer->internal_ip.s_addr == ip.s_addr) {
			return peer;
		}
	}
	return NULL;
}