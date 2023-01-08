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
	peer->is_init             = false;
	peer->inbound_encrypted   = false; 
	peer->outbound_encrypted  = false;
	peer->is_authed           = false;
	peer->is_ip_set           = false;
	peer->has_route_set       = false;
	peer->tx                  = 0;
	peer->rx                  = 0;
	peer->tx_max              = 0xFFFFFFFFFFFFFFFF;
	peer->rx_max              = 0xFFFFFFFFFFFFFFFF;
	peer->last_ping           = chipvpn_get_time();

	list_clear(&peer->routes);

	list_clear(&peer->inbound_firewall);
	list_clear(&peer->outbound_firewall);

	peer->sock_inbound = chipvpn_bucket_create(sizeof(VPNPacket) * 5);
	peer->sock_outbound = chipvpn_bucket_create(sizeof(VPNPacket) * 5);

	peer->vpn_inbound = chipvpn_bucket_create(sizeof(VPNPacket) * 5);
	peer->vpn_outbound = chipvpn_bucket_create(sizeof(VPNPacket) * 5);

	// Allow all inbound/outbound traffic on peer
	if(!chipvpn_firewall_add_rule(&peer->outbound_firewall, "0.0.0.0/0", RULE_ALLOW)) {
		chipvpn_error("unable to add firewall rule");
	}
	if(!chipvpn_firewall_add_rule(&peer->inbound_firewall, "0.0.0.0/0", RULE_ALLOW)) {
		chipvpn_error("unable to add firewall rule");
	}

	peer->inbound_cipher = chipvpn_crypto_create();
	if(!peer->inbound_cipher) {
		chipvpn_error("unable to set aes ctx for peer");
	}

	peer->outbound_cipher = chipvpn_crypto_create();
	if(!peer->outbound_cipher) {
		chipvpn_error("unable to set aes ctx for peer");
	}

	chipvpn_log("peer connected");
	return peer;
}

void chipvpn_peer_free(VPNPeer *peer) {
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

	chipvpn_bucket_free(peer->sock_inbound);
	chipvpn_bucket_free(peer->sock_outbound);

	chipvpn_bucket_free(peer->vpn_inbound);
	chipvpn_bucket_free(peer->vpn_outbound);

	chipvpn_crypto_free(peer->inbound_cipher);
	chipvpn_crypto_free(peer->outbound_cipher);

	free(peer);
}

void chipvpn_peer_disconnect(VPNPeer *peer) {
	// flush remaining outbound buffer
	while(chipvpn_peer_cipher_outbound(peer) > 0) {}
	chipvpn_peer_socket_outbound(peer);

	chipvpn_log("peer disconnected");
	list_remove(&peer->node);
	close(peer->fd);
	chipvpn_peer_free(peer);
}

int chipvpn_peer_socket_inbound(VPNPeer *peer) {
	int size = chipvpn_bucket_write_available(peer->sock_inbound);

	if(size > 0) {
		char buf[size];
		int r = recv(peer->fd, buf, size, MSG_DONTWAIT);
		if(r <= 0) {
			if(errno == EAGAIN || errno == EWOULDBLOCK) {
				return VPN_EAGAIN;
			}
			return VPN_CONNECTION_END;
		}

		return chipvpn_bucket_write(peer->sock_inbound, buf, r);
	}
	return VPN_EAGAIN;
}

int chipvpn_peer_socket_outbound(VPNPeer *peer) {
	int size = chipvpn_bucket_read_available(peer->sock_outbound);

	if(size > 0) {
		int w = send(peer->fd, chipvpn_bucket_get_buffer(peer->sock_outbound), size, MSG_DONTWAIT);
		if(w <= 0) {
			if(errno == EAGAIN || errno == EWOULDBLOCK) {
				return VPN_EAGAIN;
			}
			return VPN_CONNECTION_END;
		}

		return chipvpn_bucket_consume(peer->sock_outbound, w);
	}
	return VPN_EAGAIN;
}

int chipvpn_peer_cipher_inbound(VPNPeer *peer) {
	if(peer->inbound_encrypted) {
		VPNBucket *src = peer->sock_inbound;
		VPNBucket *dst = peer->vpn_inbound;

		int size = MIN(chipvpn_bucket_read_available(src), chipvpn_bucket_write_available(dst));
		size = MIN(size, 1024);

		if(size > 0) {
			char src_buf[size], dst_buf[size];
			int r = chipvpn_bucket_read(src, src_buf, size);

			if(!chipvpn_crypto_decrypt(peer->inbound_cipher, dst_buf, src_buf, r)) {
				return VPN_CONNECTION_END;
			}

			return chipvpn_bucket_write(dst, dst_buf, r);
		}
	}
	return VPN_EAGAIN;
}

int chipvpn_peer_cipher_outbound(VPNPeer *peer) {
	if(peer->inbound_encrypted) {
		VPNBucket *src = peer->vpn_outbound;
		VPNBucket *dst = peer->sock_outbound;

		int size = MIN(chipvpn_bucket_read_available(src), chipvpn_bucket_write_available(dst));
		size = MIN(size, 1024);

		if(size > 0) {
			char src_buf[size], dst_buf[size];
			int r = chipvpn_bucket_read(src, src_buf, size);

			if(!chipvpn_crypto_encrypt(peer->outbound_cipher, dst_buf, src_buf, r)) {
				return VPN_CONNECTION_END;
			}

			return chipvpn_bucket_write(dst, dst_buf, r);
		}
	}
	return VPN_EAGAIN;
}

int chipvpn_peer_recv(VPNPeer *peer, VPNPacket *dst) {
	VPNBucket *bucket = peer->sock_inbound;
	if(peer->inbound_encrypted) {
		bucket = peer->vpn_inbound;
	}

	if(chipvpn_bucket_read_available(bucket) >= sizeof(VPNPacketHeader)) {
		VPNPacket *packet = (VPNPacket*)chipvpn_bucket_get_buffer(bucket);

		int size = sizeof(VPNPacketHeader) + PLEN(packet);

		if(size > sizeof(VPNPacket)) {
			return VPN_CONNECTION_END;
		}

		if(chipvpn_bucket_read_available(bucket) >= size) {
			return chipvpn_bucket_read(bucket, dst, size);
		}
	}
	return VPN_EAGAIN;
}

int chipvpn_peer_send(VPNPeer *peer, VPNPacketType type, void *data, uint16_t size, VPNPacketFlag flag) {
	VPNBucket *bucket = peer->sock_outbound;
	if(peer->outbound_encrypted) {
		bucket = peer->vpn_outbound;
	}

	if(
		(
			flag == VPN_FLAG_DATA && 
			chipvpn_bucket_write_available(bucket) >= sizeof(VPNPacketHeader) + size
		)
		||
		(
			flag == VPN_FLAG_CONTROL
		)
	) {
		VPNPacket packet = {
			.header.size = htons(size),
			.header.type = (uint8_t)(type & 0xFF)
		};

		if(data && size > 0) {
			memcpy(&packet.data, data, size);
		}

		return chipvpn_bucket_write(bucket, &packet, sizeof(VPNPacketHeader) + size);
	}
	return VPN_EAGAIN;
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