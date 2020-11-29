#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include "chipvpn.h"

void update_ping(Peer *peer) {
	if(peer) {
		peer->last_ping = time(NULL);
	}
}

bool is_unpinged(Peer *peer) {
	if(peer) {
		return (time(NULL) - peer->last_ping) >= 10;
	}
	return true;
}

void socket_peer_send(Socket *socket, Peer *peer, char *data, int size, SendType type) {
	// send_peer: Packet sequencing and reliability layer
	// Packet fragmentation will be handled in socket_send_fragment

	Packet packet;
	packet.header.type     = htonl(PT_DATA);
	packet.header.session  = peer->session;
	packet.header.size     = htonl(size);

	packet.header.seqid    = htonl(peer->seqid);
	packet.header.ackid    = htonl(peer->ackid);

	if(data != NULL) {
		memcpy((char*)&packet.data, data, size);
	}
	socket_send_fragment(socket, (char*)&packet, sizeof(PacketHeader) + size, peer->addr);
}

uint32_t get_peer_free_ip(List *peers) {
	uint32_t start = inet_addr("10.0.0.100");
	uint32_t end   = inet_addr("10.0.0.200");
	bool     trip  = false;

	for(uint32_t ip = ntohl(start); ip < ntohl(end); ip++) {
		trip = false;
		for(ListNode *i = list_begin(peers); i != list_end(peers); i = list_next(i)) {
			Peer *peer = (Peer*)i;
			if(peer->internal_ip == htonl(ip)) {
				trip = true;
			}
		}
		if(trip == false) {
			return htonl(ip);
		}
	}

	return 0;
}

Peer *get_peer_by_ip(List *peers, uint32_t ip) {
	for(ListNode *i = list_begin(peers); i != list_end(peers); i = list_next(i)) {
		Peer *peer = (Peer*)i;
		if(peer->internal_ip == ip) {
			return peer;
		}
	}
	return NULL;
}

Peer *get_peer_by_session(List *peers, Session session) {
	for(ListNode *i = list_begin(peers); i != list_end(peers); i = list_next(i)) {
		Peer *peer = (Peer*)i;
		if(memcmp(&peer->session, &session, sizeof(Session)) == 0) {
			return peer;
		}
	}
	return NULL;
}