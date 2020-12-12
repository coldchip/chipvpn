#include "chipsock.h"

int chip_host_event(Socket *socket, SocketEvent *event) {
	// @return: 0 = not ready, > 0 data available
	if((chip_proto_get_time() - socket->last_service_time) >= PING_INTERVAL) {
		ListNode *i = list_begin(&socket->frag_queue);
		while(i != list_end(&socket->frag_queue)) {
			FragmentEntry *entry = (FragmentEntry*)i;
			i = list_next(i);
			if(chip_proto_get_time() > entry->expiry) {
				chip_proto_free_frag(entry);
			}
		}

		for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
			if(chip_peer_is_unpinged(peer)) {
				// Set peer to STATE_DISCONNECTING
				if(peer->state == STATE_CONNECTED) {
					chip_peer_disconnect(peer);
				}
				if(peer->state == STATE_CONNECTING) {
					// no notify because not connected at the first place
					peer->state = STATE_DISCONNECTED;
					event->type = EVENT_CONNECT_TIMEOUT;
					event->peer = peer;
					return 1;
				}
			}
			if(peer->state == STATE_DISCONNECTING) {
				// Disconnect & notify
				ListNode *x = list_begin(&peer->ack_queue);
				while(x != list_end(&peer->ack_queue)) {
					ACKEntry *entry = (ACKEntry*)x;
					x = list_next(x);
					chip_peer_free_ack(entry);
				}
				peer->state = STATE_DISCONNECTED;
				event->type = EVENT_DISCONNECT;
				event->peer = peer;
				return 1;
			} 
			if(peer->state == STATE_CONNECTED) {
				chip_peer_ping(peer);
			}

			if(peer->state == STATE_CONNECTED || peer->state == STATE_CONNECTING) {
				ListNode *x = list_begin(&peer->ack_queue);
				while(x != list_end(&peer->ack_queue)) {
					ACKEntry *entry = (ACKEntry*)x;
					x = list_next(x);
					chip_proto_send_fragment(peer->socket, entry->packet, entry->size, peer->addr);
				}
			}
		}
		socket->last_service_time = chip_proto_get_time();
	}

	event->type = EVENT_NONE;
	event->peer = NULL;

	Packet packet;
	struct sockaddr_in addr;
	if(chip_proto_recv_fragment(socket, (char*)&packet, sizeof(Packet), &addr)) {
		int      packet_type    = ntohl(packet.header.type);
		int      packet_size    = ntohl(packet.header.size);
		uint32_t packet_seqid   = ntohl(packet.header.seqid);
		uint32_t packet_session = ntohl(packet.header.session);

		Peer *peer = NULL;

		if((packet_type & PT_CONNECT)) {
			// Do connect server side
			peer = chip_proto_handle_connect(socket, packet_session, addr);
		} else {
			peer = chip_peer_get_by_session(socket, packet_session);
		}

		if(
			(peer) && 
			((peer->addr.sin_addr.s_addr != addr.sin_addr.s_addr) ||
			(peer->addr.sin_port != addr.sin_port))
		) {
			// Reject packets that does not match ip addr of peer's
			return 0;
		}

		if(peer && (packet_type & PT_ACK_REPLY)) {
			chip_peer_remove_ack(peer, packet_seqid);
			return 0;
		}

		if(peer && (packet_type & PT_RETRANSMIT)) {
			ACKEntry *entry = chip_peer_get_ack(peer, packet_seqid);
			if(entry) {
				chip_proto_send_fragment(peer->socket, entry->packet, entry->size, peer->addr);
			}
			return 0;
		}

		if(peer && (packet_type & PT_ACK)) {
			
			if(packet_seqid > peer->incoming_seqid) {
				PacketHeader header;
				header.type  = PT_RETRANSMIT;
				header.seqid = peer->incoming_seqid;
				chip_peer_send_outgoing_command(peer, &header, NULL, 0);
				return 0;
			} else if(packet_seqid == peer->incoming_seqid) {
				PacketHeader header;
				header.type  = PT_ACK_REPLY;
				header.seqid = packet_seqid;
				chip_peer_send_outgoing_command(peer, &header, NULL, 0);
				peer->incoming_seqid++;
			} else {
				return 0;
			}
		}
		
		if(peer) {
			if(packet_type & PT_CONNECT_VERIFY) {
				if(chip_proto_handle_verify_connect(socket, peer)) {
					event->type = EVENT_CONNECT;
					event->peer = peer;
					return 1;
				}
			} else if(packet_type & PT_PING) {
				printf("%i peer(s) left\n", chip_peer_count_connected(socket));
				chip_peer_update_ping(peer);
			} else if(packet_type & PT_DATA && (packet_size > 0 && packet_size < 65535)) {
				event->data = malloc(sizeof(char) * packet_size);
				event->size = packet_size;
				memcpy(event->data, (char*)&packet.data, packet_size);
				event->type = EVENT_RECEIVE;
				event->peer = peer;
				return 1;
			}
		}
		
	}

	return 0;
}

Peer *chip_proto_handle_connect(Socket *socket, uint32_t session, struct sockaddr_in addr) {
	Peer *peer = chip_peer_get_disconnected(socket);
	if(peer) {
		peer->socket         = socket;
		peer->state          = STATE_CONNECTING;
		peer->addr           = addr;
		peer->incoming_seqid = 0;
		peer->outgoing_seqid = 0;
		peer->session        = session;
		list_clear(&peer->ack_queue);
		chip_peer_update_ping(peer);

		PacketHeader header;
		header.type = PT_CONNECT_VERIFY | PT_ACK;
		chip_peer_send_outgoing_command(peer, &header, NULL, 0);

		return peer;
	}
	return NULL;
}

bool chip_proto_handle_verify_connect(Socket *socket, Peer *peer) {
	if(peer->state == STATE_CONNECTING) {
		peer->state = STATE_CONNECTED;

		PacketHeader header;
		header.type = PT_CONNECT_VERIFY | PT_ACK;
		chip_peer_send_outgoing_command(peer, &header, NULL, 0);
		return true;
	}
	return false;
}

void chip_proto_send_fragment(Socket *socket, void *data, int size, struct sockaddr_in addr) {
	uint32_t id = rand();

	Fragment fragment;
	int mss    = 1200;
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

bool chip_proto_recv_fragment(Socket *socket, void *data, int size, struct sockaddr_in *addr) {
	socklen_t len = sizeof(struct sockaddr_in);

	Fragment fragment;

	if(recvfrom(socket->fd, (char*)&fragment, sizeof(Fragment), MSG_DONTWAIT, (struct sockaddr *)addr, &len) > 0) {
		chip_proto_insert_frag(socket, fragment, *addr);
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
						chip_proto_remove_frag(socket, head_id);
						return true;
					}
				} else {
					chip_proto_remove_frag(socket, head_id);
					return false;
				}
			}
		}
	}

	return false;
}

void chip_proto_insert_frag(Socket *socket, Fragment fragment, struct sockaddr_in addr) {
	FragmentEntry *entry = malloc(sizeof(FragmentEntry));
	entry->expiry        = chip_proto_get_time() + 2;
	entry->addr          = addr;
	entry->fragment      = fragment;

	list_insert(list_end(&socket->frag_queue), entry);

	if(list_size(&socket->frag_queue) > socket->queue_size) {
		FragmentEntry *current = (FragmentEntry*)list_begin(&socket->frag_queue);
		chip_proto_free_frag(current);
	}
}

void chip_proto_remove_frag(Socket *socket, uint32_t id) {
	ListNode *i = list_begin(&socket->frag_queue);

	while(i != list_end(&socket->frag_queue)) {
		FragmentEntry *current = (FragmentEntry*)i;
		i = list_next(i);
		if(ntohl(current->fragment.header.id) == id) {
			chip_proto_free_frag(current);
		}
	}
}

void chip_proto_free_frag(FragmentEntry *entry) {
	list_remove(&entry->node);
	free(entry);
}

uint32_t chip_proto_get_time() {
	// Second precision
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000) / 1000;
}