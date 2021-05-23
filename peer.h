#ifndef PEER_H
#define PEER_H

#include "list.h"
#include "packet.h"
#include "aes.h"
#include <stdint.h>
#include <stdbool.h>

typedef struct _VPNPeer {
	ListNode node;
	int fd;
	bool is_authed;
	uint32_t last_ping;
	uint32_t internal_ip;

	uint64_t tx;
	uint64_t rx;

	unsigned int buffer_pos;
	char buffer[sizeof(VPNPacket) + 256]; // idk

	struct AES_ctx ctx;
} VPNPeer;

VPNPeer           *chipvpn_peer_alloc(int fd);
void               chipvpn_peer_dealloc(VPNPeer *peer);
int                chipvpn_peer_recv_packet(VPNPeer *peer, VPNPacket *dst);
int                chipvpn_peer_send_packet(VPNPeer *peer, VPNPacketType type, void *data, int size);
int                chipvpn_peer_raw_recv(VPNPeer *peer, void *buf, int size);
int                chipvpn_peer_raw_send(VPNPeer *peer, void *buf, int size);
uint32_t           chipvpn_get_peer_free_ip(List *peers, char *gateway);
VPNPeer           *chipvpn_get_peer_by_ip(List *peers, uint32_t ip);

#endif