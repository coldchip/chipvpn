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
	list_clear(&socket->ack_queue);
	return socket;
}

bool socket_bind(Socket *socket, struct sockaddr_in addr) {
	if(bind(socket->fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) { 
		return true;
	}
	return false;
}

int get_socket_fd(Socket *socket) {
	return socket->fd;
}

void socket_service(Socket *socket) {
	ListNode *i = list_begin(&socket->frag_queue);
	while(i != list_end(&socket->frag_queue)) {
		FragmentEntry *entry = (FragmentEntry*)i;
		i = list_next(i);
		if(time(NULL) > entry->expiry) {
			// Free fragment if it expires
			free_frag_entry(entry);
		}
	}

	ListNode *e = list_begin(&socket->ack_queue);
	while(e != list_end(&socket->ack_queue)) {
		ACKEntry *entry = (ACKEntry*)e;
		e = list_next(e);
		if(time(NULL) > entry->expiry) {
			// Delete ACK if it expires
			free_ack_entry(entry);
		} else {
			// Resend ACK
			send_peer_frag(socket, entry->id, entry->data, entry->size, entry->addr, RELIABLE);
		}
	}
}

void send_peer(Socket *socket, void *data, int size, struct sockaddr_in addr, SendType type) {
	uint32_t rand_id = rand();

	send_peer_frag(socket, rand_id, data, size, addr, type);

	if(type == RELIABLE) {
		// Queue if type is reliable
		ack_queue_insert(socket, rand_id, data, size, addr);
	}
}

void send_peer_frag(Socket *socket, uint32_t id, void *data, int size, struct sockaddr_in addr, SendType type) {
	Fragment fragment;
	int mss    = 1300;
	int pieces = floor(size / mss);

	for(int i = 0; i <= pieces; i++) {
		int offset = i * mss;
		int frag_size  = i == pieces ? size - offset : mss;
		fragment.header.type     = htonl(type);
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

bool recv_peer(Socket *socket, void *data, int size, struct sockaddr_in *addr) {
	socklen_t len = sizeof(struct sockaddr_in);

	Fragment fragment;

	if(recvfrom(socket->fd, (char*)&fragment, sizeof(Fragment), MSG_WAITALL, (struct sockaddr *)addr, &len) > 0) {
		SendType type = ntohl(fragment.header.type);
		uint32_t id   = ntohl(fragment.header.id);
		if(type == ACK) {
			ack_queue_remove(socket, id);
		} else {
			frag_queue_insert(socket, fragment, *addr);
		}
	}

	for(ListNode *i = list_begin(&socket->frag_queue); i != list_end(&socket->frag_queue); i = list_next(i)) {
		FragmentEntry *head_entry = (FragmentEntry*)i;
		SendType type       = ntohl(head_entry->fragment.header.type);
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
						if(type == RELIABLE) {
							send_peer_frag(socket, head_id, NULL, 0, head_entry->addr, ACK);
						}
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





void ack_queue_insert(Socket *socket, uint32_t id, char *data, int size, struct sockaddr_in addr) {
	ACKEntry *entry = malloc(sizeof(ACKEntry));
	entry->expiry = time(NULL) + 10;
	entry->id     = id;
	entry->data   = malloc(sizeof(char) * size);
	entry->size   = size;
	entry->addr   = addr;

	memcpy(entry->data, data, size);

	list_insert(list_end(&socket->ack_queue), entry);

	if(list_size(&socket->ack_queue) > socket->queue_size) {
		ACKEntry *current = (ACKEntry*)list_begin(&socket->ack_queue);
		free_ack_entry(current);
	}
}

void ack_queue_remove(Socket *socket, uint32_t id) {
	ListNode *i = list_begin(&socket->ack_queue);

	while(i != list_end(&socket->ack_queue)) {
		ACKEntry *current = (ACKEntry*)i;
		i = list_next(i);
		if(current->id == id) {
			free_ack_entry(current);
		}
	}
}

void free_ack_entry(ACKEntry *entry) {
	list_remove(&entry->node);
	free(entry->data);
	free(entry);
}