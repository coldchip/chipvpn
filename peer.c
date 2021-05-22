#include "peer.h"
#include "packet.h"
#include "chipvpn.h"
#include "crypto.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

VPNPeer *chipvpn_peer_alloc(int fd) {
	VPNPeer *peer = malloc(sizeof(VPNPeer));
	peer->fd = fd;
	peer->tx = 0;
	peer->rx = 0;
	peer->last_ping = chipvpn_get_time();
	peer->buffer_pos = 0;
	console_log("client connected");
	return peer;
}

void chipvpn_peer_dealloc(VPNPeer *peer) {
	list_remove(&peer->node);
	console_log("client disconnected");
	close(peer->fd);
	free(peer);
}

int chipvpn_peer_recv_packet(VPNPeer *peer, VPNPacket *dst) {
	VPNPacket *packet = (VPNPacket*)&peer->buffer;
	uint32_t size     = ntohl(packet->header.size);
	uint32_t left     = sizeof(VPNPacketHeader);

	if(peer->buffer_pos >= sizeof(VPNPacketHeader)) {
		left += size - peer->buffer_pos;
	}

	if((left + peer->buffer_pos) < sizeof(peer->buffer)) {
		int readed = chipvpn_peer_raw_recv(peer, &peer->buffer[peer->buffer_pos], left);
		if(readed > 0) {
			peer->buffer_pos += readed;
		} else {
			// connection close
			return -1;
		}
	} else {
		// corrupted buffer ?!
		return -1;
	}

	size = ntohl(packet->header.size); // refresh size

	if(peer->buffer_pos == (size + sizeof(VPNPacketHeader))) {
		// Buffer ready
		peer->buffer_pos = 0;
		chipvpn_decrypt_buf((char*)&packet->data, size);
		memcpy(dst, packet, sizeof(VPNPacket));
		memset(peer->buffer, 0, sizeof(peer->buffer));
		return 1;
	}

	return 0; // no event
}

void chipvpn_peer_send_packet(VPNPeer *peer, VPNPacketType type, void *data, int size) {
	VPNPacket *packet = alloca(sizeof(VPNPacket) + size); // faster than malloc
	packet->header.size = htonl(size);
	packet->header.type = htonl(type);
	if(data) {
		memcpy((char*)&packet->data, data, size);
		chipvpn_encrypt_buf((char*)&packet->data, size);
	}
	chipvpn_peer_raw_send(peer, (char*)packet, sizeof(packet->header) + size);
}

int chipvpn_peer_raw_recv(VPNPeer *peer, void *buf, int size) {
	int n = recv(peer->fd, buf, size, 0);
	return n;
}

int chipvpn_peer_raw_send(VPNPeer *peer, void *buf, int size) {
	return send(peer->fd, buf, size, 0);
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