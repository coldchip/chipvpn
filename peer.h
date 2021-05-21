#ifndef PEER_H
#define PEER_H

#include "list.h"
#include "packet.h"
#include <stdint.h>
#include <stdbool.h>
#include <openssl/ssl.h>

typedef struct _VPNPeer {
	ListNode node;
	SSL *ssl;
	int fd;
	bool is_authed;
	uint32_t last_ping;
	uint32_t internal_ip;

	uint64_t tx;
	uint64_t rx;

	unsigned int buffer_pos;
	char buffer[16384];
} VPNPeer;

VPNPeer           *chipvpn_peer_alloc(int fd);
void               chipvpn_peer_dealloc(VPNPeer *peer);
void               chipvpn_peer_send_packet(VPNPeer *peer, VPNPacketType type, void *data, int size);
int                chipvpn_peer_raw_recv(VPNPeer *peer, void *buf, int size);
int                chipvpn_peer_raw_send(VPNPeer *peer, void *buf, int size);
uint32_t           chipvpn_get_peer_free_ip(List *peers, char *gateway);
VPNPeer           *chipvpn_get_peer_by_ip(List *peers, uint32_t ip);

#endif