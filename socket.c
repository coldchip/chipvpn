#include <stdbool.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include "chipvpn.h"

void socket_service(Socket *socket) {
	List *resend_queue = &socket->tx_queue;

	ListNode *i = list_begin(resend_queue);
	while(i != list_end(resend_queue)) {
		ReceiptQueue *currentQueue = (ReceiptQueue*)i;

		i = list_next(i);

		if((time(NULL) - currentQueue->time) >= 2) {
			send_peer(socket, currentQueue->seqid, currentQueue->data, currentQueue->size, &currentQueue->addr, RELIABLE);
			list_remove(&currentQueue->node);
			free(currentQueue->data);
			free(currentQueue);
		}
	}
}

void send_peer(Socket *socket, int seqid, void *data, int size, struct sockaddr_in *addr, SendType type) {
	List *receipt_queue = &socket->tx_queue;

	Fragment fragment;
	int mss    = 1000;
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

		encrypt((char*)&fragment, sizeof(Fragment));
		if(sendto(socket->fd, (char*)&fragment, sizeof(FragmentHeader) + frag_size, MSG_CONFIRM, (struct sockaddr *)addr, sizeof(struct sockaddr)) != sizeof(Fragment)) {
			//printf("send_peer error\n");
		}
	}
	
	if(type == RELIABLE && list_size(receipt_queue) <= 50) {
		ReceiptQueue *r_queue = malloc(sizeof(FragmentQueue));
		//memcpy(&(current_queue->packet), &fragment, sizeof(Fragment));
		char *data_q = malloc(size);
		memcpy(data_q, data, size);
		r_queue->seqid = seqid;
		r_queue->size  = size;
		r_queue->data  = data_q;
		r_queue->addr  = *addr;
		r_queue->time  = time(NULL);
		list_insert(list_end(receipt_queue), r_queue);
	}
	
}

void remove_receipt_from_queue(List *queue, int to_remove) {
	ListNode *i = list_begin(queue);
	while(i != list_end(queue)) {
		ReceiptQueue *currentQueue = (ReceiptQueue*)i;

		i = list_next(i);

		int id = currentQueue->seqid;

		if(to_remove == id) {
			list_remove(&currentQueue->node);
			free(currentQueue);
			free(currentQueue->data);
		}
	}
}

void remove_id_from_queue(List *queue, int to_remove) {
	ListNode *i = list_begin(queue);
	while(i != list_end(queue)) {
		FragmentQueue *currentQueue = (FragmentQueue*)i;
		Fragment *current = (Fragment*)&(currentQueue->packet);

		i = list_next(i);

		int id = ntohl(current->header.id);

		if(to_remove == id) {
			list_remove(&currentQueue->node);
			free(currentQueue);
		}
	}
}

bool recv_peer(Socket *socket, void *data, int size, struct sockaddr_in *addr) {
	List *defrag_queue  = &socket->defrag_queue;
	List *receipt_queue = &socket->tx_queue;
	int   queue_size    = 50;

	socklen_t len = sizeof(struct sockaddr);
	Fragment fragment;

	// Receive Fragment(s)
	if(recvfrom(socket->fd, (char*)&fragment, sizeof(Fragment), MSG_DONTWAIT, (struct sockaddr *)addr, &len) > 0) {
		decrypt((char*)&fragment, sizeof(Fragment));

		FragmentQueue *current_queue = malloc(sizeof(FragmentQueue));
		memcpy(&(current_queue->packet), &fragment, sizeof(Fragment));
		list_insert(list_end(defrag_queue), current_queue);
		if(list_size(defrag_queue) > queue_size) {
			FragmentQueue *current = (FragmentQueue*)list_begin(defrag_queue);
			list_remove(&current->node);
			free(current);
		}
	}
	// Fragment(s) Reassembly
	for(ListNode *i = list_begin(defrag_queue); i != list_end(defrag_queue); i = list_next(i)) {
		Fragment *head    = (Fragment*)&((FragmentQueue*)i)->packet;

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
				Fragment *current = (Fragment*)&((FragmentQueue*)l)->packet;

				//int  frag      = ntohl(current->header.fragment);
				int  id        = ntohl(current->header.id);
				int  offset    = ntohl(current->header.offset);
				int  frag_size = ntohl(current->header.size);

				if((head_id == id) && offset + frag_size <= size) {
					memcpy(data + offset, (char*)&current->data, frag_size);
					if(received_frag >= head_max_frag) {
						remove_id_from_queue(defrag_queue, id);
						if(head_type == RELIABLE) {
							int tt = 0;
							send_peer(socket, head_seqid, &tt, sizeof(int), addr, ACK);
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