#include "peer.h"
#include "packet.h"
#include "chipvpn.h"
#include "crypto.h"
#include "rc4.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>

VPNPeer *chipvpn_peer_alloc(int fd) {
	char key[32] = {
		0xc3, 0xc7, 0x91, 0x59, 0xc3, 0x46, 0x62, 0x8a, 
		0xfe, 0xf4, 0x6f, 0xf0, 0x87, 0x58, 0x8d, 0x0e, 
		0x02, 0x78, 0xaf, 0x91, 0x49, 0x52, 0xc3, 0xd4, 
		0x32, 0x17, 0xb1, 0x3f, 0x67, 0xd9, 0xcb, 0xac 
	};

	VPNPeer *peer = malloc(sizeof(VPNPeer));
	peer->fd = fd;
	peer->tx = 0;
	peer->rx = 0;
	peer->last_ping = chipvpn_get_time();
	peer->buffer_pos = 0;
	peer->inbound_rc4 = rc4_create((uint8_t*)&key, sizeof(key));
	peer->outbound_rc4 = rc4_create((uint8_t*)&key, sizeof(key));
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

int chipvpn_peer_recv_packet(VPNPeer *peer, VPNPacket *dst) {
	VPNPacket *packet = (VPNPacket*)&peer->buffer;
	uint32_t preamble = ntohl(packet->header.preamble);
	uint32_t size     = ntohl(packet->header.size);
	uint32_t left     = sizeof(VPNPacketHeader) - peer->buffer_pos;

	if(peer->buffer_pos >= sizeof(VPNPacketHeader)) {
		if(preamble != 48484848) {
			// TODO: fix
			return VPN_CONNECTION_PACKET_CORRUPTED;
		}
		left += size;
	}

	if(
		(peer->buffer_pos < sizeof(peer->buffer)) && 
		(left + peer->buffer_pos) < sizeof(peer->buffer)
	) {
		int readed = chipvpn_peer_raw_recv(peer, &peer->buffer[peer->buffer_pos], left);
		if(readed > 0) {
			peer->buffer_pos += readed;
		} else {
			// connection close
			return VPN_CONNECTION_END;
		}
	} else {
		// packet size too large
		return VPN_CONNECTION_PACKET_OVERFLOW;
	}

	size = ntohl(packet->header.size); // refresh size

	if(peer->buffer_pos == (size + sizeof(VPNPacketHeader))) {
		// Buffer ready
		peer->buffer_pos = 0;

		memcpy(dst, packet, sizeof(VPNPacket));
		memset(peer->buffer, 0, sizeof(peer->buffer));
		return VPN_DATA_AVAILABLE;
	}

	return VPN_NO_EVENT; // no event
}

int chipvpn_peer_send_packet(VPNPeer *peer, VPNPacketType type, void *data, int size) {
	VPNPacket *packet       = alloca(sizeof(VPNPacketHeader) + size); // faster than malloc
	packet->header.preamble = htonl(48484848);
	packet->header.size     = htonl(size);
	packet->header.type     = htonl(type);
	if(data) {
		memcpy((char*)&packet->data, data, size);
	}
	return chipvpn_peer_raw_send(peer, (char*)packet, sizeof(VPNPacketHeader) + size);
}

int chipvpn_peer_raw_recv(VPNPeer *peer, void *buf, int size) {
	int r = recv(peer->fd, buf, size, 0);
	if(r > 0) {
		chipvpn_decrypt_buf(peer, (char*)buf, r);
	}
	return r;
}

int chipvpn_peer_raw_send(VPNPeer *peer, void *buf, int size) {
	if(size > 0) {
		chipvpn_encrypt_buf(peer, (char*)buf, size);
	}
	int w = send(peer->fd, buf, size, 0);
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