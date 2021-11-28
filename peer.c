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

#include "peer.h"
#include "packet.h"
#include "chipvpn.h"
#include "crypto.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

VPNPeer *chipvpn_peer_new(int fd) {
	VPNPeer *peer             = malloc(sizeof(VPNPeer));
	peer->fd                  = fd;
	peer->is_authed           = false;
	peer->tx                  = 0;
	peer->rx                  = 0;
	peer->tx_max              = 0xFFFFFFFFFFFFFFFF;
	peer->rx_max              = 0xFFFFFFFFFFFFFFFF;
	peer->last_ping           = chipvpn_get_time();
	peer->inbound_buffer_pos  = 0;
	peer->outbound_buffer_pos = 0;

	list_clear(&peer->inbound_firewall);
	list_clear(&peer->outbound_firewall);

	chipvpn_peer_logout(peer);

	peer->inbound_aes = crypto_new();
	if(!peer->inbound_aes) {
		error("unable to set aes ctx for peer");
	}

	peer->outbound_aes = crypto_new();
	if(!peer->outbound_aes) {
		error("unable to set aes ctx for peer");
	}

	console_log("peer connected");
	return peer;
}

void chipvpn_peer_free(VPNPeer *peer) {
	chipvpn_peer_logout(peer);

	while(!list_empty(&peer->inbound_firewall)) {
		VPNPeerRule *rule = (VPNPeerRule*)list_remove(list_begin(&peer->inbound_firewall));
		chipvpn_peer_free_rule(rule);
	}

	while(!list_empty(&peer->outbound_firewall)) {
		VPNPeerRule *rule = (VPNPeerRule*)list_remove(list_begin(&peer->outbound_firewall));
		chipvpn_peer_free_rule(rule);
	}

	crypto_free(peer->inbound_aes);
	crypto_free(peer->outbound_aes);
	free(peer);
}

void chipvpn_peer_disconnect(VPNPeer *peer) {
	console_log("peer disconnected");
	list_remove(&peer->node);
	close(peer->fd);
	chipvpn_peer_free(peer);

	//if(config->mode == MODE_CLIENT) {
	//	terminate = true;
	//}
}

void chipvpn_peer_set_key(VPNPeer *peer, char *key) {
	char iv[] = { 
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f 
	};

	crypto_set_key(peer->inbound_aes, key, iv);
	crypto_set_key(peer->outbound_aes, key, iv);
}

bool chipvpn_peer_readable(VPNPeer *peer) {
	// Able to receive a fully constructed VPNPacket datagram
	VPNPacket *packet = (VPNPacket*)&peer->inbound_buffer;

	return 
	peer->inbound_buffer_pos >= sizeof(VPNPacketHeader) && 
	peer->inbound_buffer_pos == (sizeof(VPNPacketHeader) + PLEN(packet));
}

bool chipvpn_peer_writeable(VPNPeer *peer) {
	// Able to send a fully constructed VPNPacket datagram
	return (!peer->outbound_buffer_pos) > 0;
}

int chipvpn_peer_dispatch_inbound(VPNPeer *peer) {
	if(!chipvpn_peer_readable(peer)) {
		VPNPacket *packet = (VPNPacket*)&peer->inbound_buffer;
		uint32_t left     = sizeof(VPNPacketHeader) - peer->inbound_buffer_pos;

		if(peer->inbound_buffer_pos >= sizeof(VPNPacketHeader)) {
			left += PLEN(packet);
		}

		if(
			(peer->inbound_buffer_pos > sizeof(peer->inbound_buffer)) || 
			(left + peer->inbound_buffer_pos) > sizeof(peer->inbound_buffer)
		) {
			return VPN_CONNECTION_END;
		}

		int err = EWOULDBLOCK;
		int r = chipvpn_peer_raw_recv(peer, &peer->inbound_buffer[peer->inbound_buffer_pos], left, &err);
		if(r <= 0) {
			if(err == EWOULDBLOCK || err == EAGAIN) {
				return VPN_EAGAIN;
			}
			return VPN_CONNECTION_END;
		}

		peer->inbound_buffer_pos += r;
		return r;
	}
	return VPN_EAGAIN;
}

int chipvpn_peer_dispatch_outbound(VPNPeer *peer) {
	if(!chipvpn_peer_writeable(peer)) {
		VPNPacket *packet = (VPNPacket*)&peer->outbound_buffer;

		int err = EWOULDBLOCK;
		int sent = chipvpn_peer_raw_send(peer, &peer->outbound_buffer[(sizeof(VPNPacketHeader) + PLEN(packet)) - peer->outbound_buffer_pos], peer->outbound_buffer_pos, &err);
		if(sent <= 0) {
			if(err == EWOULDBLOCK || err == EAGAIN) {
				return VPN_EAGAIN;
			}
			return VPN_CONNECTION_END;
		}

		peer->outbound_buffer_pos -= sent;
		return sent;
	}

	return VPN_EAGAIN;
}

bool chipvpn_peer_recv(VPNPeer *peer, VPNPacket *dst) {
	if(chipvpn_peer_readable(peer)) {
		VPNPacket *packet = (VPNPacket*)&peer->inbound_buffer;
		// Buffer ready
		peer->inbound_buffer_pos = 0;

		memcpy(dst, packet, sizeof(VPNPacketHeader) + PLEN(packet));

		return true;
	}

	return false;
}

bool chipvpn_peer_send(VPNPeer *peer, VPNPacketType type, void *data, int size) {
	int r = chipvpn_peer_dispatch_outbound(peer);
	if(r <= 0 && r != VPN_EAGAIN) {
		return false;
	}

	if(chipvpn_peer_writeable(peer)) {
		VPNPacket *packet   = (VPNPacket*)peer->outbound_buffer;
		packet->header.size = htonl(size);
		packet->header.type = (uint8_t)(type);
		if(data && size > 0) {
			memcpy(&packet->data, data, size);
		}

		peer->outbound_buffer_pos = sizeof(VPNPacketHeader) + size;

	} else {
		return false;
	}

	r = chipvpn_peer_dispatch_outbound(peer);
	if(r <= 0 && r != VPN_EAGAIN) {
		return false;
	}

	return true;
}

int chipvpn_peer_raw_recv(VPNPeer *peer, void *buf, int size, int *err) {
	/*
		*buf should not be modified as that will 
		corrupt the program from reading the
		correct packet size. 
	*/
	int r = recv(peer->fd, buf, size, 0);
	if(err) {
		*err = errno;
	}
	return r;
}

int chipvpn_peer_raw_send(VPNPeer *peer, void *buf, int size, int *err) {
	/*
		*buf should not be modified as that will 
		corrupt the program from reading the
		correct packet size. 
	*/
	int w = send(peer->fd, buf, size, 0);
	if(err) {
		*err = errno;
	}
	return w;
}

bool chipvpn_peer_get_free_ip(List *peers, struct in_addr gateway, struct in_addr *assign) {
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

bool chipvpn_peer_is_authed(VPNPeer *peer) {
	return peer->is_authed;
}

void chipvpn_peer_login(VPNPeer *peer) {
	peer->is_authed = true;
}

void chipvpn_peer_logout(VPNPeer *peer) {
	peer->is_authed = false;
}

VPNPeerRule *chipvpn_peer_new_rule(const char *cidr) {
	uint32_t ip, mask;
	if(cidr_to_ip_and_mask(cidr, &ip, &mask)) {
		VPNPeerRule *rule = malloc(sizeof(VPNPeerRule));
		rule->ip     = ip;
		rule->mask = mask;
		return rule;
	}
	return NULL;
}

bool chipvpn_peer_add_inbound_rule(VPNPeer *peer, const char *cidr) {
	VPNPeerRule *rule = chipvpn_peer_new_rule(cidr);
	if(rule) {
		list_insert(list_begin(&peer->inbound_firewall), rule);
		return true;
	}
	return false;
}

bool chipvpn_peer_add_outbound_rule(VPNPeer *peer, const char *cidr) {
	VPNPeerRule *rule = chipvpn_peer_new_rule(cidr);
	if(rule) {
		list_insert(list_begin(&peer->outbound_firewall), rule);
		return true;
	}
	return false;
}

bool chipvpn_peer_match_inbound_rule(VPNPeer *peer, uint32_t ip) {
	for(ListNode *i = list_begin(&peer->inbound_firewall); i != list_end(&peer->inbound_firewall); i = list_next(i)) {
		VPNPeerRule *rule = (VPNPeerRule*)i;
		uint32_t start = rule->ip & rule->mask;
		uint32_t end   = rule->ip | ~rule->mask;
		if(ip >= start && ip <= end) {
			return true;
		}
	}
	return false;
}

bool chipvpn_peer_match_outbound_rule(VPNPeer *peer, uint32_t ip) {
	for(ListNode *i = list_begin(&peer->outbound_firewall); i != list_end(&peer->outbound_firewall); i = list_next(i)) {
		VPNPeerRule *rule = (VPNPeerRule*)i;
		uint32_t start = rule->ip & rule->mask;
		uint32_t end   = rule->ip | ~rule->mask;
		if(ip >= start && ip <= end) {
			return true;
		}
	}
	return false;
}

void chipvpn_peer_free_rule(VPNPeerRule *rule) {
	free(rule);
}