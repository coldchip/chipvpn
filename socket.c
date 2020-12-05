#include "socket.h"

Socket *new_socket(int peer_count) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		return NULL;
	}
	Socket *socket = malloc(sizeof(Socket));
	socket->fd                = sock;
	socket->last_service_time = 0;
	socket->queue_size        = 50;
	socket->peer_count        = peer_count;
	list_clear(&socket->frag_queue);
	list_clear(&socket->ack_queue);
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

	Peer *peer           = malloc(sizeof(Peer));
	peer->socket         = socket;
	peer->state          = STATE_CONNECTING;
	peer->addr           = addr;
	peer->incoming_seqid = 0;
	peer->outgoing_seqid = 0;
	peer->session        = rand();
	list_clear(&peer->ack_queue);
	socket_peer_update_ping(peer);
	list_insert(list_end(&socket->peers), peer);

	PacketHeader header;
	header.type = PT_CONNECT | PT_ACK;

	socket_peer_send_outgoing_command(peer, &header, NULL, 0);
}

int get_socket_fd(Socket *socket) {
	return socket->fd;
}

int socket_event(Socket *socket, SocketEvent *event) {
	// @return: 0 = not ready, > 0 data available
	if((time(NULL) - socket->last_service_time) >= PING_INTERVAL) {
		ListNode *i = list_begin(&socket->frag_queue);
		while(i != list_end(&socket->frag_queue)) {
			FragmentEntry *entry = (FragmentEntry*)i;
			i = list_next(i);
			if(time(NULL) > entry->expiry) {
				free_frag_entry(entry);
			}
		}

		ListNode *j = list_begin(&socket->peers);
		while(j != list_end(&socket->peers)) {
			Peer *peer = (Peer*)j;
			j = list_next(j);
			if(socket_peer_is_unpinged(peer) && (peer->state == STATE_CONNECTED || peer->state == STATE_CONNECTING)) {
				// Set peer to STATE_DISCONNECTING and wait for notify
				socket_peer_disconnect(peer);
			} else if(peer->state == STATE_DISCONNECTING) {
				// Notify disconnect
				peer->state = STATE_DISCONNECTED;

				event->type = EVENT_DISCONNECT;
				event->peer = peer;
				return 1;
			} else if(peer->state == STATE_DISCONNECTED) {
				// Remove notified & disconnected peers
				ListNode *x = list_begin(&peer->ack_queue);
				while(x != list_end(&peer->ack_queue)) {
					ACKEntry *entry = (ACKEntry*)x;
					x = list_next(x);
					list_remove(&entry->node);
					free(entry->packet);
					free(entry);
				}

				list_remove(&peer->node);
				free(peer);
				continue;
			} else if(peer->state == STATE_CONNECTED) {
				socket_peer_ping(peer);
			}

			if(peer->state == STATE_CONNECTED || peer->state == STATE_CONNECTING) {
				ListNode *x = list_begin(&peer->ack_queue);
				while(x != list_end(&peer->ack_queue)) {
					ACKEntry *entry = (ACKEntry*)x;
					x = list_next(x);
					socket_send_fragment(peer->socket, entry->packet, entry->size, peer->addr);
				}
			}
		}
		socket->last_service_time = time(NULL);
	}

	event->type = EVENT_NONE;
	event->peer = NULL;

	Packet packet;
	struct sockaddr_in addr;
	if(socket_recv_fragment(socket, (char*)&packet, sizeof(Packet), &addr)) {
		int      packet_type    = ntohl(packet.header.type);
		int      packet_size    = ntohl(packet.header.size);
		uint32_t packet_seqid   = ntohl(packet.header.seqid);
		uint32_t packet_session = ntohl(packet.header.session);

		Peer *peer = NULL;

		if((packet_type & PT_CONNECT)) {
			// Do connect server side
			peer = socket_handle_connect(socket, packet_session, addr);
		} else {
			peer = socket_peer_get_by_session(socket, packet_session);
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
			socket_peer_remove_ack(peer, packet_seqid);
			return 0;
		}

		if(peer && (packet_type & PT_RETRANSMIT)) {
			ListNode *x = list_begin(&peer->ack_queue);
			while(x != list_end(&peer->ack_queue)) {
				ACKEntry *entry = (ACKEntry*)x;
				x = list_next(x);
				if(entry->seqid == packet_seqid) {
					socket_send_fragment(peer->socket, entry->packet, entry->size, peer->addr);
				}
			}
			return 0;
		}

		if(peer && (packet_type & PT_ACK)) {
			
			if(packet_seqid > peer->incoming_seqid) {
				PacketHeader header;
				header.type  = PT_RETRANSMIT;
				header.seqid = peer->incoming_seqid;
				socket_peer_send_outgoing_command(peer, &header, NULL, 0);
				return 0;
			} else if(packet_seqid == peer->incoming_seqid) {
				PacketHeader header;
				header.type  = PT_ACK_REPLY;
				header.seqid = packet_seqid;
				socket_peer_send_outgoing_command(peer, &header, NULL, 0);
				peer->incoming_seqid++;
			} else {
				return 0;
			}
		}
		
		if(peer) {
			if(packet_type & PT_CONNECT_VERIFY) {
				if(socket_handle_verify_connect(socket, peer)) {
					event->type = EVENT_CONNECT;
					event->peer = peer;
					return 1;
				}
			} else if(packet_type & PT_PING) {
				printf("%li peer(s) left\n", list_size(&socket->peers));
				socket_peer_update_ping(peer);
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

Peer *socket_handle_connect(Socket *socket, uint32_t session, struct sockaddr_in addr) {
	if(list_size(&socket->peers) < socket->peer_count) {
		Peer *peer           = malloc(sizeof(Peer));
		peer->socket         = socket;
		peer->state          = STATE_CONNECTING;
		peer->addr           = addr;
		peer->incoming_seqid = 0;
		peer->outgoing_seqid = 0;
		peer->session        = session;
		list_clear(&peer->ack_queue);
		socket_peer_update_ping(peer);
		list_insert(list_end(&socket->peers), peer);

		PacketHeader header;
		header.type = PT_CONNECT_VERIFY | PT_ACK;
		socket_peer_send_outgoing_command(peer, &header, NULL, 0);

		return peer;
	}
	return NULL;
}

bool socket_handle_verify_connect(Socket *socket, Peer *peer) {
	if(peer->state == STATE_CONNECTING) {
		peer->state = STATE_CONNECTED;

		PacketHeader header;
		header.type = PT_CONNECT_VERIFY | PT_ACK;
		socket_peer_send_outgoing_command(peer, &header, NULL, 0);
		return true;
	}
	return false;
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

	if(recvfrom(socket->fd, (char*)&fragment, sizeof(Fragment), MSG_DONTWAIT, (struct sockaddr *)addr, &len) > 0) {
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

void socket_fill_random(char *buffer, int size) {
    syscall(SYS_getrandom, buffer, size, 1);
}

void socket_free(Socket *socket) {
	close(socket->fd);
	free(socket);
}