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
	peer->encrypted           = false;
	peer->is_authed           = false;
	peer->tx                  = 0;
	peer->rx                  = 0;
	peer->tx_max              = 0xFFFFFFFFFFFFFFFF;
	peer->rx_max              = 0xFFFFFFFFFFFFFFFF;
	peer->last_ping           = chipvpn_get_time();
	peer->has_route_set       = false;
	peer->inbound_buffer_pos  = 0;
	peer->outbound_buffer_pos = 0;

	list_clear(&peer->routes);

	list_clear(&peer->inbound_firewall);
	list_clear(&peer->outbound_firewall);

	list_clear(&peer->inbound_queue);
	list_clear(&peer->outbound_queue);

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

	// inbound queue cleanup
	while(!list_empty(&peer->inbound_firewall)) {
		VPNPacketQueue *queue = (VPNPacketQueue*)list_remove(list_begin(&peer->inbound_queue));
		free(queue);
	}

	// outbound queue cleanup
	while(!list_empty(&peer->outbound_firewall)) {
		VPNPacketQueue *queue = (VPNPacketQueue*)list_remove(list_begin(&peer->outbound_queue));
		free(queue);
	}

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

void chipvpn_peer_set_encryption(VPNPeer *peer, bool encrypted) {
	peer->encrypted = encrypted;
}

bool chipvpn_peer_get_encryption(VPNPeer *peer) {
	return peer->encrypted;
}

void chipvpn_peer_set_login(VPNPeer *peer, bool login) {
	peer->is_authed = login;
}

bool chipvpn_peer_get_login(VPNPeer *peer) {
	return peer->is_authed;
}

bool chipvpn_peer_buffer_readable(VPNPeer *peer) {
	// Able to receive a fully constructed VPNPacket datagram
	VPNPacket *packet = &peer->inbound_buffer;

	return 
	peer->inbound_buffer_pos >= sizeof(VPNPacketHeader) && 
	peer->inbound_buffer_pos == (sizeof(VPNPacketHeader) + PLEN(packet));
}

bool chipvpn_peer_buffer_writeable(VPNPeer *peer) {
	// Able to send a fully constructed VPNPacket datagram
	return peer->outbound_buffer_pos == 0;
}

/*
	The chipvpn_peer_enqueue_service function is called when the input buffer 
	of the VPNPeer object is readable and the inbound queue has fewer than CHIPVPN_QUEUE_SIZE. 
	In this case, the function allocates a new VPNPacketQueue object and initializes 
	it with the current contents of the VPNPeer's inbound buffer. It then inserts the 
	VPNPacketQueue object into the end of the inbound queue and resets the position of 
	the inbound buffer to zero. The function returns true if the VPNPacketQueue object 
	was added to the inbound queue, and false otherwise.
*/

bool chipvpn_peer_enqueue_service(VPNPeer *peer) {
	if(chipvpn_peer_buffer_readable(peer) && list_size(&peer->inbound_queue) < CHIPVPN_QUEUE_SIZE) {
		VPNPacketQueue *queue = malloc(sizeof(VPNPacketQueue));
		
		peer->inbound_buffer_pos = 0;
		queue->packet = peer->inbound_buffer;

		list_insert(list_end(&peer->inbound_queue), queue);

		return true;
	}

	return false;
}

/*
	The chipvpn_peer_dequeue_service function is called when the output buffer of 
	the VPNPeer buffer is writeable and the outbound queue has at least one element. 
	In this case, the function removes the first element from the outbound queue and 
	initializes the VPNPeer's outbound buffer with its contents. It then sets the 
	position of the outbound buffer to the size of the VPNPacketHeader plus the size 
	of the packet body, as indicated by the packet header. The function returns true if 
	the outbound buffer was successfully initialized, and false otherwise.
*/

bool chipvpn_peer_dequeue_service(VPNPeer *peer) {
	if(chipvpn_peer_buffer_writeable(peer) && list_size(&peer->outbound_queue) > 0) {
		VPNPacketQueue *queue = (VPNPacketQueue*)list_remove(list_begin(&peer->outbound_queue));

		peer->outbound_buffer_pos = sizeof(VPNPacketHeader) + ntohl(queue->packet.header.size);
		peer->outbound_buffer = queue->packet;

		free(queue);

		return true;
	}

	return false;
}

int chipvpn_peer_dispatch_inbound(VPNPeer *peer) {
	if(!chipvpn_peer_buffer_readable(peer)) {
		VPNPacket *packet = &peer->inbound_buffer;
		uint32_t left = sizeof(VPNPacketHeader) - peer->inbound_buffer_pos;

		if(peer->inbound_buffer_pos >= sizeof(VPNPacketHeader)) {
			if(PLEN(packet) > sizeof(VPNPacketBody)) {
				return VPN_CONNECTION_END;
			}
			left += PLEN(packet);
		}

		if(
			(peer->inbound_buffer_pos > sizeof(peer->inbound_buffer)) || 
			(left + peer->inbound_buffer_pos) > sizeof(peer->inbound_buffer)
		) {
			return VPN_CONNECTION_END;
		}

		int err = EWOULDBLOCK;
		int r = chipvpn_peer_raw_recv(peer, ((char*)packet) + peer->inbound_buffer_pos, left, &err);
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
	if(!chipvpn_peer_buffer_writeable(peer)) {
		VPNPacket *packet = &peer->outbound_buffer;

		int err = EWOULDBLOCK;
		int w = chipvpn_peer_raw_send(peer, ((char*)packet) + sizeof(VPNPacketHeader) + PLEN(packet) - peer->outbound_buffer_pos, peer->outbound_buffer_pos, &err);
		if(w <= 0) {
			if(err == EWOULDBLOCK || err == EAGAIN) {
				return VPN_EAGAIN;
			}
			return VPN_CONNECTION_END;
		}

		peer->outbound_buffer_pos -= w;
		return w;
	}

	return VPN_EAGAIN;
}

bool chipvpn_peer_recv(VPNPeer *peer, VPNPacket *dst) {
	if(list_size(&peer->inbound_queue) > 0) {
		VPNPacketQueue *queue = (VPNPacketQueue*)list_remove(list_begin(&peer->inbound_queue));
		// Buffer ready
		
		VPNPacket *packet = &queue->packet;

		memcpy(&dst->header, &packet->header, sizeof(VPNPacketHeader));

		if(chipvpn_peer_get_encryption(peer)) {
			if(!chipvpn_crypto_decrypt(peer->inbound_aes, &dst->data, &packet->data, PLEN(packet))) {
				free(queue);
				return false;
			}
		} else {
			memcpy(&dst->data, &packet->data, PLEN(packet));
		}

		free(queue);

		return true;
	}

	return false;
}

bool chipvpn_peer_send(VPNPeer *peer, VPNPacketType type, void *data, int size, VPNPacketFlag flag) {
	if(
		(
			flag == VPN_FLAG_DATA && 
			list_size(&peer->outbound_queue) < (CHIPVPN_QUEUE_SIZE)
		) 
		||
		(
			flag == VPN_FLAG_CONTROL && 
			list_size(&peer->outbound_queue) < (CHIPVPN_QUEUE_SIZE + CHIPVPN_PRIORITY_QUEUE_SIZE)
		)
	) {
		VPNPacketQueue *queue = malloc(sizeof(VPNPacketQueue));
		list_insert(list_end(&peer->outbound_queue), queue);

		VPNPacket *packet   = &queue->packet;
		packet->header.size = htonl(size);
		packet->header.type = (uint8_t)(type & 0xff);
		if(data && size > 0) {
			if(chipvpn_peer_get_encryption(peer)) {
				if(!chipvpn_crypto_encrypt(peer->outbound_aes, &packet->data, data, size)) {
					list_remove(&queue->node);
					free(queue);
					return false;
				}
			} else {
				memcpy(&packet->data, data, size);
			}
		}

		return true;
	}
	return false;
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