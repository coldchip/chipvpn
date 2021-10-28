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
	
	list_clear(&peer->inbound_queue);
	list_clear(&peer->outbound_queue);
	
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

int chipvpn_peer_dispatch_inbound(VPNPeer *peer) {
	VPNPacket *packet = (VPNPacket*)&peer->inbound_buffer;
	uint32_t left     = sizeof(VPNPacketHeader) - peer->inbound_buffer_pos;

	if(peer->inbound_buffer_pos >= sizeof(VPNPacketHeader)) {
		left += PLEN(packet);
	}

	if(
		(left + peer->inbound_buffer_pos) > sizeof(peer->inbound_buffer)
	) {
		return VPN_CONNECTION_PACKET_OVERFLOW;
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

	if(
		peer->inbound_buffer_pos >= sizeof(VPNPacketHeader) && 
		peer->inbound_buffer_pos == (sizeof(VPNPacketHeader) + PLEN(packet))
	) {
		// Buffer ready
		peer->inbound_buffer_pos = 0;

		VPNPacketQueue *queue = malloc(sizeof(VPNPacketQueue));
		memcpy(&queue->packet, packet, sizeof(VPNPacketHeader) + PLEN(packet));
		
		list_insert(list_end(&peer->inbound_queue), queue);
	}

	return r;
}

int chipvpn_peer_dispatch_outbound(VPNPeer *peer) {
	if(list_size(&peer->outbound_queue) > 0) {
		VPNPacketQueue *queue   = list_back(&peer->outbound_queue);
		VPNPacket *packet       = &queue->packet; 

		int err = EWOULDBLOCK;
		int w = chipvpn_peer_raw_send(peer, (char*)packet + sizeof(VPNPacketHeader) + PLEN(packet) - queue->rw_offset, queue->rw_offset, &err);
		if(w <= 0) {
			if(err == EWOULDBLOCK || err == EAGAIN) {
				// no data yet
				return VPN_EAGAIN;
			}
			// connection close
			return VPN_CONNECTION_END;
		}

		queue->rw_offset -= w;
		if(queue->rw_offset == 0) {
			list_remove(&queue->node);
			free(queue);
		}
		return w;
	}
	return VPN_EAGAIN;
}

int chipvpn_peer_recv_nio(VPNPeer *peer, VPNPacket *dst) {
	if(list_size(&peer->inbound_queue) > 0) {
		VPNPacketQueue *queue   = list_back(&peer->inbound_queue);
		VPNPacket *packet       = &queue->packet; 

		memcpy(dst, packet, sizeof(VPNPacketHeader) + PLEN(packet));

		list_remove(&queue->node);
		free(queue);

		return sizeof(VPNPacketHeader) + PLEN(packet);
	}

	return VPN_EAGAIN; // no event
}

int chipvpn_peer_send_nio(VPNPeer *peer, VPNPacketType type, void *data, int size) {
	VPNPacketQueue *queue   = malloc(sizeof(VPNPacketQueue));
	queue->rw_offset        = sizeof(VPNPacketHeader) + size;

	queue->packet.header.preamble = htonl(48484848);
	queue->packet.header.size     = htonl(size);
	queue->packet.header.type     = htonl(type);
	if(data) {
		memcpy(&queue->packet.data, data, size);
	}

	list_insert(list_end(&peer->outbound_queue), queue);

	return sizeof(VPNPacketHeader) + size;
}

int chipvpn_peer_raw_recv(VPNPeer *peer, void *buf, int size, int *err) {
	int r = recv(peer->fd, buf, size, 0);

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