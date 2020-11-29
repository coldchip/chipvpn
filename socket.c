#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include "chipvpn.h"

Socket *new_socket() {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		return NULL;
	}
	Socket *socket = malloc(sizeof(Socket));
	socket->fd = sock;

	socket->queue_size = 50;
	list_clear(&socket->frag_queue);
	list_clear(&socket->peers);
	return socket;
}

bool socket_bind(Socket *socket, char *ip, int port) {
	struct sockaddr_in     addr;
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip); 
	addr.sin_port        = htons(port);

	if(bind(socket->fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) { 
		return true;
	}
	return false;
}

void socket_connect(Socket *socket, char *ip, int port) {
	struct sockaddr_in     addr;
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip); 
	addr.sin_port        = htons(port);

	Packet packet;
	packet.header.type    = htonl(PT_CONNECT_SYN);
	packet.header.size    = htonl(0);
	packet.header.seqid   = htonl(10);
	packet.header.ackid   = htonl(0);

	socket_send_fragment(socket, (char*)&packet, sizeof(PacketHeader), addr);
}

int get_socket_fd(Socket *socket) {
	return socket->fd;
}

void socket_service(Socket *socket) {
	int count = 0;
	ListNode *i = list_begin(&socket->peers);
	while(i != list_end(&socket->peers)) {
		Peer *peer = (Peer*)i;

		i = list_next(i);

		count++;

		Packet packet;
		packet.header.type     = htonl(PT_PING);
		packet.header.session  = peer->session;
		packet.header.size     = htonl(0);
		packet.header.seqid    = htonl(peer->seqid);
		packet.header.ackid    = htonl(peer->ackid);
		socket_send_fragment(socket, (char*)&packet, sizeof(PacketHeader), peer->addr);

		if(is_unpinged(peer)) {
			printf("PEER delete\n");
			list_remove(&peer->node);
			free(peer);
		}
	}

	ListNode *j = list_begin(&socket->frag_queue);
	while(j != list_end(&socket->frag_queue)) {
		FragmentEntry *entry = (FragmentEntry*)j;
		j = list_next(j);
		if(time(NULL) > entry->expiry) {
			// Free fragment if it expires
			free_frag_entry(entry);
		}
	}
}

void socket_send(Socket *socket, Peer *peer, char *data, int size, SendType type) {
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

int socket_recv(Socket *socket, Peer **peer, char *data, int size, EventType *type) {
	// @return: -1 = error, 0 = not ready, > 0 data available
	Packet packet;
	struct sockaddr_in addr;
	if(!socket_recv_fragment(socket, (char*)&packet, sizeof(Packet), &addr)) {
		*type = EVENT_NONE;
		return 0;
	}

	int      packet_type    = ntohl(packet.header.type);
	int      packet_size    = ntohl(packet.header.size);
	uint32_t packet_seqid   = ntohl(packet.header.seqid);
	uint32_t packet_ackid   = ntohl(packet.header.ackid);
	Session  packet_session = packet.header.session;

	if(packet_type == PT_CONNECT_SYN) {
		// Do connect server side
		Peer *peer_alloc  = malloc(sizeof(Peer));
		peer_alloc->addr  = addr;
		peer_alloc->seqid = 0;
		peer_alloc->ackid = packet_seqid + 1;
		update_ping(peer_alloc);
		fill_random((char*)&peer_alloc->session, sizeof(Session));
		list_insert(list_end(&socket->peers), peer_alloc);

		Packet synack;
		synack.header.type     = htonl(PT_CONNECT_ACK);
		synack.header.session  = peer_alloc->session;
		synack.header.size     = htonl(size);

		synack.header.seqid    = htonl(0);
		synack.header.ackid    = htonl(0);

		socket_send_fragment(socket, (char*)&synack, sizeof(PacketHeader), addr);
		*peer = peer_alloc;
		*type = EVENT_CONNECT;
		printf("CONNECT SYN\n");
		return 1;
	} else if(packet_type == PT_CONNECT_ACK) {
		// Client side
		Peer *peer_alloc = malloc(sizeof(Peer));
		peer_alloc->addr    = addr;
		peer_alloc->seqid   = 0;
		peer_alloc->ackid   = packet_seqid + 1;
		peer_alloc->session = packet_session;
		update_ping(peer_alloc);

		list_insert(list_end(&socket->peers), peer_alloc);
		*peer = peer_alloc;
		*type = EVENT_CONNECT;
		printf("CONNECT ACK\n");
		return 1;
	} else {
		*peer = get_peer_by_session(&socket->peers, packet_session);
		if(*peer) {
			if(packet_type == PT_PING) {
				printf("Update peer, %li peer(s) left\n", list_size(&socket->peers));
				update_ping(*peer);
			} else {
				// TODO: check for packet_size to prevent buffer overflow
				memcpy(data, (char*)&packet.data, packet_size);
				*type = EVENT_RECEIVE;
				return packet_size;
			}
		}
	}
	*type = EVENT_NONE;
	return -1;
}

void socket_send_fragment(Socket *socket, void *data, int size, struct sockaddr_in addr) {
	uint32_t id = rand();

	Fragment fragment;
	int mss    = 1300;
	int pieces = floor(size / mss);

	for(int i = 0; i <= pieces; i++) {
		int offset = i * mss;
		int frag_size  = i == pieces ? size - offset : mss;
		fragment.header.index    = htonl(i);
		fragment.header.count    = htonl(pieces);
		fragment.header.size     = htonl(frag_size);
		fragment.header.id       = htonl(id);
		fragment.header.offset   = htonl(i * mss);
		if(data != NULL) {
			memcpy((char*)&fragment.data, data + offset, frag_size);
		}

		if(sendto(socket->fd, (char*)&fragment, sizeof(FragmentHeader) + frag_size, MSG_CONFIRM, (struct sockaddr *)&addr, sizeof(struct sockaddr)) != sizeof(Fragment)) {
			//printf("send_peer error\n");
		}
	}
}

bool socket_recv_fragment(Socket *socket, void *data, int size, struct sockaddr_in *addr) {
	socklen_t len = sizeof(struct sockaddr_in);

	Fragment fragment;

	if(recvfrom(socket->fd, (char*)&fragment, sizeof(Fragment), MSG_WAITALL, (struct sockaddr *)addr, &len) > 0) {
		frag_queue_insert(socket, fragment, *addr);
	}

	for(ListNode *i = list_begin(&socket->frag_queue); i != list_end(&socket->frag_queue); i = list_next(i)) {
		FragmentEntry *head_entry = (FragmentEntry*)i;
		uint32_t head_id    = ntohl(head_entry->fragment.header.id);
		uint32_t head_count = ntohl(head_entry->fragment.header.count);

		uint32_t counter = 0;

		for(ListNode *j = list_begin(&socket->frag_queue); j != list_end(&socket->frag_queue); j = list_next(j)) {
			FragmentEntry *entry = (FragmentEntry*)j;
			uint32_t entry_id     = ntohl(entry->fragment.header.id);
			uint32_t entry_offset = ntohl(entry->fragment.header.offset);
			uint32_t entry_size   = ntohl(entry->fragment.header.size);

			if(head_id == entry_id) {
				if(entry_offset + entry_size <= size) {
					counter++;
					memcpy(data + entry_offset, (char*)&entry->fragment.data, entry_size);
					if(counter > head_count) {
						frag_queue_remove(socket, head_id);
						return true;
					}
				} else {
					frag_queue_remove(socket, head_id);
					return false;
				}
			}
		}
	}

	return false;
}

void socket_free(Socket *socket) {
	close(socket->fd);
	free(socket);
}






void frag_queue_insert(Socket *socket, Fragment fragment, struct sockaddr_in addr) {
	FragmentEntry *entry = malloc(sizeof(FragmentEntry));
	entry->expiry        = time(NULL) + 2;
	entry->addr          = addr;
	entry->fragment      = fragment;

	list_insert(list_end(&socket->frag_queue), entry);

	if(list_size(&socket->frag_queue) > socket->queue_size) {
		FragmentEntry *current = (FragmentEntry*)list_begin(&socket->frag_queue);
		free_frag_entry(current);
	}
}

void frag_queue_remove(Socket *socket, uint32_t id) {
	ListNode *i = list_begin(&socket->frag_queue);

	while(i != list_end(&socket->frag_queue)) {
		FragmentEntry *current = (FragmentEntry*)i;
		i = list_next(i);
		if(ntohl(current->fragment.header.id) == id) {
			free_frag_entry(current);
		}
	}
}

void free_frag_entry(FragmentEntry *entry) {
	list_remove(&entry->node);
	free(entry);
}