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
#include "rc4.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>

VPNPeer *chipvpn_peer_alloc(int fd) {
	char key[32] = {
		0xc3, 0xc7, 0x91, 0x59, 0xc3, 0x46, 0x62, 0x8a, 
		0xfe, 0xf4, 0x6f, 0xf0, 0x87, 0x58, 0x8d, 0x0e, 
		0x02, 0x78, 0xaf, 0x91, 0x49, 0x52, 0xc3, 0xd4, 
		0x32, 0x17, 0xb1, 0x3f, 0x67, 0xd9, 0xcb, 0xac 
	};

	VPNPeer *peer             = malloc(sizeof(VPNPeer));
	peer->fd                  = fd;
	peer->tx                  = 0;
	peer->rx                  = 0;
	peer->last_ping           = chipvpn_get_time();
	peer->inbound_buffer_pos  = 0;
	peer->outbound_buffer_pos = 0;
	peer->inbound_rc4         = rc4_create((uint8_t*)&key, sizeof(key));
	peer->outbound_rc4        = rc4_create((uint8_t*)&key, sizeof(key));
	console_log("peer connected");
	return peer;
}

void chipvpn_peer_dealloc(VPNPeer *peer) {
	list_remove(&peer->node);
	console_log("peer disconnected");
	close(peer->fd);
	rc4_destroy(peer->inbound_rc4);
	rc4_destroy(peer->outbound_rc4);
	free(peer);
}

void chipvpn_set_crypto(VPNPeer *peer, char *key) {
	rc4_init(peer->inbound_rc4, (uint8_t*)key, 32);
	rc4_init(peer->outbound_rc4, (uint8_t*)key, 32);
}

int chipvpn_peer_recv_nio(VPNPeer *peer, VPNPacket *dst) {
	VPNPacket *packet = (VPNPacket*)&peer->inbound_buffer;
	uint32_t preamble = ntohl(packet->header.preamble);
	uint32_t size     = ntohl(packet->header.size);
	uint32_t left     = sizeof(VPNPacketHeader) - peer->inbound_buffer_pos;

	if(peer->inbound_buffer_pos >= sizeof(VPNPacketHeader)) {
		if(preamble != 48484848) {
			// TODO: fix
			return VPN_CONNECTION_PACKET_CORRUPTED;
		}
		left += size;
	}

	if(
		(peer->inbound_buffer_pos < sizeof(peer->inbound_buffer)) && 
		(left + peer->inbound_buffer_pos) < sizeof(peer->inbound_buffer)
	) {
		int err = EWOULDBLOCK;
		int readed = chipvpn_peer_raw_recv(peer, &peer->inbound_buffer[peer->inbound_buffer_pos], left, &err);
		if(readed > 0) {
			peer->inbound_buffer_pos += readed;
		} else {
			if(err == EWOULDBLOCK || err == EAGAIN) {
				// no data yet
				return VPN_EAGAIN;
			}
			// connection close
			return VPN_CONNECTION_END;
		}
	} else {
		// packet size too large
		return VPN_CONNECTION_PACKET_OVERFLOW;
	}

	size = ntohl(packet->header.size); // refresh size

	if(peer->inbound_buffer_pos == (size + sizeof(VPNPacketHeader))) {
		// Buffer ready
		peer->inbound_buffer_pos = 0;

		memcpy(dst, packet, sizeof(VPNPacket));
		memset(peer->inbound_buffer, 0, sizeof(peer->inbound_buffer));
		return sizeof(VPNPacketHeader) + size;
	}

	return VPN_EAGAIN; // no event
}

int chipvpn_peer_send_nio(VPNPeer *peer, VPNPacketType type, void *data, int size) {
	int sent = VPN_EAGAIN;

	if(peer->outbound_buffer_pos == 0) {
		VPNPacket *packet       = alloca(sizeof(VPNPacketHeader) + size); // faster than malloc
		packet->header.preamble = htonl(48484848);
		packet->header.size     = htonl(size);
		packet->header.type     = htonl(type);
		if(data) {
			memcpy((char*)&packet->data, data, size);
		}

		memcpy(peer->outbound_buffer, packet, sizeof(VPNPacketHeader) + size);
		peer->outbound_buffer_pos = sizeof(VPNPacketHeader) + size;

		sent = sizeof(VPNPacketHeader) + size;
	} 

	if(peer->outbound_buffer_pos > 0) {
		VPNPacket *packet = (VPNPacket*)&peer->outbound_buffer;
		uint32_t size     = ntohl(packet->header.size);

		int err = EWOULDBLOCK;
		int sent = chipvpn_peer_raw_send(peer, &peer->outbound_buffer[(sizeof(VPNPacketHeader) + size) - peer->outbound_buffer_pos], peer->outbound_buffer_pos, &err);
		if(sent > 0) {
			peer->outbound_buffer_pos -= sent;
		} else {
			if(err == EWOULDBLOCK || err == EAGAIN) {
				// no data yet
				return VPN_EAGAIN;
			}
			// connection close
			return VPN_CONNECTION_END;
		}
	}

	return sent;
}

int chipvpn_peer_raw_recv(VPNPeer *peer, void *buf, int size, int *err) {
	int r = recv(peer->fd, buf, size, MSG_DONTWAIT);

	if(err) {
		*err = errno;
	}

	if(r > 0) {
		//chipvpn_decrypt_buf(peer, (char*)buf, r);
	}
	return r;
}

int chipvpn_peer_raw_send(VPNPeer *peer, void *buf, int size, int *err) {
	if(size > 0) {
		//chipvpn_encrypt_buf(peer, (char*)buf, size);
	}
	
	int w = send(peer->fd, buf, size, MSG_DONTWAIT);
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