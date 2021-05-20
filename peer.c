#include "peer.h"
#include "packet.h"
#include "chipvpn.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>

VPNPeer *chipvpn_peer_alloc(int fd) {
	VPNPeer *peer = malloc(sizeof(VPNPeer));
	peer->ssl = NULL;
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

void chipvpn_peer_send(VPNPeer *peer, VPNPacketType type, void *data, int size) {
	VPNPacket *packet = alloca(sizeof(VPNPacket) + size); // faster than malloc
	packet->header.size = htonl(size);
	packet->header.type = htonl(type);
	if(data) {
		memcpy((char*)&packet->data, data, size);
	}
	if(peer->ssl) {
		SSL_write(peer->ssl, (char*)packet, sizeof(packet->header) + size);
	} else {
		send(peer->fd, (char*)packet, sizeof(packet->header) + size, 0);
	}
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