#include "peer.h"
#include "packet.h"
#include "chipvpn.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

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
	SSL_shutdown(peer->ssl);
    SSL_free(peer->ssl);
	close(peer->fd);
	free(peer);
}

void chipvpn_peer_send_packet(VPNPeer *peer, VPNPacketType type, void *data, int size) {
	VPNPacket *packet = alloca(sizeof(VPNPacket) + size); // faster than malloc
	packet->header.size = htonl(size);
	packet->header.type = htonl(type);
	if(data) {
		memcpy((char*)&packet->data, data, size);
	}
	chipvpn_peer_raw_send(peer, (char*)packet, sizeof(packet->header) + size);
}

int chipvpn_peer_raw_recv(VPNPeer *peer, void *buf, int size) {
	if (!SSL_is_init_finished(peer->ssl)) {
		int n = SSL_accept(peer->ssl);
		int err = SSL_get_error(peer->ssl, n);
		if(
			err == SSL_ERROR_NONE || 
			err == SSL_ERROR_WANT_READ || 
			err == SSL_ERROR_WANT_WRITE
		) {
			return 0;
		} else {
			return -1;
		}
	}
	int n = SSL_read(peer->ssl, buf, size);
	int err = SSL_get_error(peer->ssl, n);
	if(err == SSL_ERROR_NONE) {
		return n;
	} else if(
		err == SSL_ERROR_WANT_READ || 
		err == SSL_ERROR_WANT_WRITE
	) {
		return 0;
	} else {
		return -1;
	}
	
}

int chipvpn_peer_raw_send(VPNPeer *peer, void *buf, int size) {
	if (!SSL_is_init_finished(peer->ssl)) {
		int n = SSL_accept(peer->ssl);
		int err = SSL_get_error(peer->ssl, n);
		if(
			err == SSL_ERROR_NONE || 
			err == SSL_ERROR_WANT_READ || 
			err == SSL_ERROR_WANT_WRITE
		) {
			return 0;
		} else {
			return -1;
		}
	}
	int n =  SSL_write(peer->ssl, buf, size);
	int err = SSL_get_error(peer->ssl, n);
	if(err == SSL_ERROR_NONE) {
		return n;
	} else if(
		err == SSL_ERROR_WANT_READ || 
		err == SSL_ERROR_WANT_WRITE
	) {
		return 0;
	} else {
		return -1;
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