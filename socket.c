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
	list_clear(&(socket->defrag_queue));
	list_clear(&(socket->tx_queue));
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
	List *resend_queue = &socket->tx_queue;

	ListNode *i = list_begin(resend_queue);
	while(i != list_end(resend_queue)) {
		TransmitQueue *current_queue = (TransmitQueue*)i;

		i = list_next(i);

		if((time(NULL) - current_queue->time) >= 2) {
			send_peer(socket, current_queue->seqid, current_queue->data, current_queue->size, &current_queue->addr, RELIABLE);
			list_remove(&current_queue->node);
			free(current_queue->data);
			free(current_queue);
		}
	}
}

void send_peer(Socket *socket, int seqid, void *data, int size, struct sockaddr_in *addr, SendType type) {
	List *receipt_queue = &socket->tx_queue;

	Fragment fragment;
	int mss    = 1400;
	int pieces = floor(size / mss);
	int id     = rand();

	for(int i = 0; i <= pieces; i++) {
		int offset = i * mss;
		int frag_size  = i == pieces ? size - offset : mss;
		fragment.header.fragment = htonl(i);
		fragment.header.size     = htonl(frag_size);
		fragment.header.offset   = htonl(i * mss);
		fragment.header.id       = htonl(id);
		fragment.header.max_frag = htonl(pieces);
		fragment.header.seqid    = htonl(seqid);
		fragment.header.type     = htonl(type);
		memcpy((char*)&fragment.data, data + offset, frag_size);

		if(sendto(socket->fd, (char*)&fragment, sizeof(FragmentHeader) + frag_size, MSG_CONFIRM, (struct sockaddr *)addr, sizeof(struct sockaddr)) != sizeof(Fragment)) {
			//printf("send_peer error\n");
		}
	}
	
	if(type == RELIABLE && list_size(receipt_queue) <= 50) {
		TransmitQueue *tx_queue = malloc(sizeof(TransmitQueue));
		//memcpy(&(current_queue->packet), &fragment, sizeof(Fragment));
		char *data_malloc = malloc(size);
		memcpy(data_malloc, data, size);
		tx_queue->seqid = seqid;
		tx_queue->size  = size;
		tx_queue->data  = data_malloc;
		tx_queue->addr  = *addr;
		tx_queue->time  = time(NULL);
		list_insert(list_end(receipt_queue), tx_queue);
	}
	
}

void remove_receipt_from_queue(List *queue, int to_remove) {
	ListNode *i = list_begin(queue);
	while(i != list_end(queue)) {
		TransmitQueue *current_queue = (TransmitQueue*)i;

		i = list_next(i);

		int id = current_queue->seqid;

		if(to_remove == id) {
			list_remove(&current_queue->node);
			free(current_queue);
			free(current_queue->data);
		}
	}
}

void remove_id_from_queue(List *queue, int to_remove) {
	ListNode *i = list_begin(queue);
	while(i != list_end(queue)) {
		ReceiveQueue *current_queue = (ReceiveQueue*)i;
		Fragment *current = (Fragment*)&(current_queue->packet);

		i = list_next(i);

		int id = ntohl(current->header.id);

		if(to_remove == id) {
			list_remove(&current_queue->node);
			free(current_queue);
		}
	}
}

bool recv_peer(Socket *socket, void *data, int size, struct sockaddr_in *addr) {
	List *defrag_queue  = &socket->defrag_queue;
	List *receipt_queue = &socket->tx_queue;
	int   queue_size    = 20;

	socklen_t len = sizeof(struct sockaddr);
	Fragment fragment;

	// Receive Fragment(s)
	if(recvfrom(socket->fd, (char*)&fragment, sizeof(Fragment), MSG_DONTWAIT, (struct sockaddr *)addr, &len) > 0) {

		ReceiveQueue *current_queue = malloc(sizeof(ReceiveQueue));
		memcpy(&(current_queue->packet), &fragment, sizeof(Fragment));
		list_insert(list_end(defrag_queue), current_queue);
		if(list_size(defrag_queue) > queue_size) {
			ReceiveQueue *current = (ReceiveQueue*)list_begin(defrag_queue);
			list_remove(&current->node);
			free(current);
		}
	}
	// Fragment(s) Reassembly
	for(ListNode *i = list_begin(defrag_queue); i != list_end(defrag_queue); i = list_next(i)) {
		Fragment *head    = (Fragment*)&((ReceiveQueue*)i)->packet;

		int head_frag      = ntohl(head->header.fragment);
		int head_max_frag  = ntohl(head->header.max_frag);
		int head_id        = ntohl(head->header.id);
		int head_seqid     = ntohl(head->header.seqid);
		SendType head_type = ntohl(head->header.type);

		if(head_type == ACK) {
			remove_id_from_queue(defrag_queue, head_id);
			remove_receipt_from_queue(receipt_queue, head_seqid);
			return false;
		}

		if(head_frag == 0 && head_max_frag < queue_size) {
			int received_frag = 0;
			for(ListNode *l = list_begin(defrag_queue); l != list_end(defrag_queue); l = list_next(l)) {
				Fragment *current = (Fragment*)&((ReceiveQueue*)l)->packet;

				//int  frag      = ntohl(current->header.fragment);
				int  id        = ntohl(current->header.id);
				int  offset    = ntohl(current->header.offset);
				int  frag_size = ntohl(current->header.size);

				if((head_id == id) && offset + frag_size <= size) {
					memcpy(data + offset, (char*)&current->data, frag_size);
					if(received_frag >= head_max_frag) {
						remove_id_from_queue(defrag_queue, id);
						if(head_type == RELIABLE) {
							send_peer(socket, head_seqid, NULL, 0, addr, ACK);
						}
						return true;
					}
					received_frag++;
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