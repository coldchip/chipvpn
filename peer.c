#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include "chipvpn.h"

Peers *new_peer_container(int peerCount) {
	Peers *peers_container = malloc(sizeof(Peers));
	Peer *peers = malloc(sizeof(Peer) * peerCount);
	for(Peer *peer = peers; peer < &peers[peerCount]; ++peer) {
		peer->state = DISCONNECTED;
	}
	peers_container->peers = peers;
	peers_container->peerCount = peerCount;
	return peers_container;
}

void free_peer_container(Peers *peers) {
	if(peers && peers->peers) {
		free(peers->peers);
	}
	free(peers);
}

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

Peer *get_disconnected_peer(Peers *peers) {
	for(Peer *peer = peers->peers; peer < &peers->peers[peers->peerCount]; ++peer) {
		if(is_disconnected(peer)) {
			return peer;
		}
	}
	return NULL;
}

uint32_t get_peer_free_ip(Peers *peers) {
	uint32_t start = inet_addr("10.0.0.100");
	uint32_t end   = inet_addr("10.0.0.200");
	bool     trip  = false;

	for(int i = ntohl(start); i < ntohl(end); i++) {
		trip = false;
		for(Peer *peer = peers->peers; peer < &peers->peers[peers->peerCount]; ++peer) {
			if(is_connected(peer) && peer->internal_ip == htonl(i)) {
				trip = true;
			}
		}
		if(trip == false) {
			return htonl(i);
		}
	}

	return 0;
}

Peer *get_peer_by_ip(Peers *peers, uint32_t ip) {
	for(Peer *peer = peers->peers; peer < &peers->peers[peers->peerCount]; ++peer) {
		if(is_connected(peer) && peer->internal_ip == ip) {
			return peer;
		}
	}
	return NULL;
}

Peer *get_peer_by_session(Peers *peers, Session session) {
	for(Peer *peer = peers->peers; peer < &peers->peers[peers->peerCount]; ++peer) {
		if(is_connected(peer) && memcmp(&peer->session, &session, sizeof(Session)) == 0) {
			return peer;
		}
	}
	return NULL;
}

bool is_connected(Peer *peer) {
	return peer->state == CONNECTED;
}

bool is_disconnected(Peer *peer) {
	return peer->state == DISCONNECTED;
}