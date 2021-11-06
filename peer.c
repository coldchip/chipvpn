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
	char key[] = {
		0xc3, 0xc7, 0x91, 0x59, 0xc3, 0x46, 0x62, 0x8a, 
		0xfe, 0xf4, 0x6f, 0xf0, 0x87, 0x58, 0x8d, 0x0e, 
		0x02, 0x78, 0xaf, 0x91, 0x49, 0x52, 0xc3, 0xd4, 
		0x32, 0x17, 0xb1, 0x3f, 0x67, 0xd9, 0xcb, 0xac 
	};

	VPNPeer *peer             = malloc(sizeof(VPNPeer));
	peer->fd                  = fd;
	peer->is_authed           = false;
	peer->tx                  = 0;
	peer->rx                  = 0;
	peer->last_ping           = chipvpn_get_time();
	peer->inbound_buffer_pos  = 0;
	peer->outbound_buffer_pos = 0;

	peer->inbound_aes = crypto_new();
	if(!peer->inbound_aes) {
		error("unable to set aes ctx for peer");
	}

	peer->outbound_aes = crypto_new();
	if(!peer->outbound_aes) {
		error("unable to set aes ctx for peer");
	}

	chipvpn_set_key(peer, key);

	console_log("peer connected");
	return peer;
}

void chipvpn_peer_free(VPNPeer *peer) {
	crypto_free(peer->inbound_aes);
	crypto_free(peer->outbound_aes);
	free(peer);
}

void chipvpn_set_key(VPNPeer *peer, char *key) {
	char iv[] = { 
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f 
	};

	printf("set key ");
	for(int i = 0; i < 32; i++) {
		printf("%02x", key[i] & 0xff);
	}
	printf("\n");

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

int chipvpn_peer_recv(VPNPeer *peer, VPNPacket *dst) {
	if(chipvpn_peer_readable(peer)) {
		VPNPacket *packet = (VPNPacket*)&peer->inbound_buffer;
		// Buffer ready
		peer->inbound_buffer_pos = 0;

		memcpy(dst, packet, sizeof(VPNPacketHeader) + PLEN(packet));

		return sizeof(VPNPacketHeader) + PLEN(packet);
	}

	return VPN_EAGAIN; // no event
}

int chipvpn_peer_send(VPNPeer *peer, VPNPacketType type, void *data, int size) {
	int sent = VPN_EAGAIN;

	int r = chipvpn_peer_dispatch_outbound(peer);
	if(r <= 0 && r != VPN_EAGAIN) {
		return r;
	}

	if(chipvpn_peer_writeable(peer)) {
		VPNPacket *packet   = (VPNPacket*)peer->outbound_buffer;
		packet->header.size = htonl(size);
		packet->header.type = (uint8_t)(type);
		if(data && size > 0) {
			memcpy(&packet->data, data, size);
		}

		peer->outbound_buffer_pos = sizeof(VPNPacketHeader) + size;

		sent = peer->outbound_buffer_pos;
	}

	r = chipvpn_peer_dispatch_outbound(peer);
	if(r <= 0 && r != VPN_EAGAIN) {
		return r;
	}

	return sent;
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

uint32_t chipvpn_get_peer_free_ip(List *peers, char *gateway) {
	uint32_t start = inet_addr(gateway) + (1   << 24);
	uint32_t end   = inet_addr(gateway) + (200 << 24);
	bool     trip  = false;

	for(uint32_t ip = ntohl(start); ip < ntohl(end); ip++) {
		trip = false;
		for(ListNode *i = list_begin(peers); i != list_end(peers); i = list_next(i)) {
			VPNPeer *peer = (VPNPeer*)i;
			if((peer->internal_ip == htonl(ip))) {
				trip = true;
			}
		}
		if(trip == false) {
			return htonl(ip);
		}
	}

	return 0;
}

VPNPeer *chipvpn_get_peer_by_ip(List *peers, uint32_t ip) {
	for(ListNode *i = list_begin(peers); i != list_end(peers); i = list_next(i)) {
		VPNPeer *peer = (VPNPeer*)i;
		if((peer->internal_ip == ip)) {
			return peer;
		}
	}
	return NULL;
}