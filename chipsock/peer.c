#include "chipsock.h"

void socket_peer_update_ping(Peer *peer) {
	if(peer) {
		peer->last_ping = time(NULL);
	}
}

bool socket_peer_is_unpinged(Peer *peer) {
	if(peer) {
		return (time(NULL) - peer->last_ping) >= 10;
	}
	return true;
}

void socket_peer_ping(Peer *peer) {
	if(peer->state == STATE_CONNECTED) {
		PacketHeader header;
		header.type = PT_PING | PT_ACK;
		socket_peer_send_outgoing_command(peer, &header, NULL, 0);
	}
}

void socket_peer_send(Peer *peer, char *data, int size, SendType type) {
	// send_peer: Packet sequencing and reliability layer
	// Packet fragmentation will be handled in socket_send_fragment
	if(peer->state == STATE_CONNECTED) {
		PacketHeader header;
		header.type = PT_DATA;
		if(type == RELIABLE) {
			header.type |= PT_ACK;
		}

		socket_peer_send_outgoing_command(peer, &header, data, size);
	}
}

void socket_peer_send_outgoing_command(Peer *peer, PacketHeader *header, char *data, int size) {
	if(peer->state != STATE_DISCONNECTED) {
		Packet packet;
		packet.header.type    = htonl(header->type);
		packet.header.size    = htonl(size);
		packet.header.session = htonl(peer->session);
		if(data) {
			memcpy((char*)&packet.data, data, size);
		}
		if(header->type == PT_ACK_REPLY || header->type == PT_RETRANSMIT) {
			packet.header.seqid = htonl(header->seqid);
		} else {
			packet.header.seqid = htonl(peer->outgoing_seqid);
			if(header->type & PT_ACK) {
				socket_peer_queue_ack(peer, peer->outgoing_seqid, (char*)&packet, sizeof(PacketHeader) + size);
				peer->outgoing_seqid++;
			}
		}
		socket_send_fragment(peer->socket, (char*)&packet, sizeof(PacketHeader) + size, peer->addr);
	}
}

void socket_peer_queue_ack(Peer *peer, uint32_t seqid, char *packet, int size) {
	if(peer->state != STATE_DISCONNECTED) {
		ACKEntry *entry = malloc(sizeof(ACKEntry));
		entry->seqid  = seqid;
		entry->packet = malloc(sizeof(char) * size);
		entry->size   = size;
		memcpy(entry->packet, packet, size);
		list_insert(list_end(&peer->ack_queue), entry);
		
		if(list_size(&peer->ack_queue) > 500) {
			socket_peer_disconnect(peer);
		}
	}
}

void socket_peer_remove_ack(Peer *peer, uint32_t seqid) {
	if(peer->state != STATE_DISCONNECTED) {
		ListNode *i = list_begin(&peer->ack_queue);

		while(i != list_end(&peer->ack_queue)) {
			ACKEntry *current = (ACKEntry*)i;
			i = list_next(i);
			if(current->seqid <= seqid) {
				list_remove(&current->node);
				free(current->packet);
				free(current);
			}
		}
	}
}

Peer *socket_peer_get_by_session(Socket *socket, uint32_t session) {
	for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
		if(peer->state != STATE_DISCONNECTED) {
			if(peer->session == session) {
				return peer;
			}
		}
	}
	return NULL;
}

void socket_peer_disconnect(Peer *peer) {
	// queue for disconnection
	peer->state = STATE_DISCONNECTING;
}

Peer *socket_peer_get_disconnected(Socket *socket) {
	for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
		if(peer->state == STATE_DISCONNECTED) {
			return peer;
		}
	}
	return NULL;
}

int socket_peer_count_connected(Socket *socket) {
	int result = 0;
	for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
		if(peer->state == STATE_CONNECTED) {
			result++;
		}
	}
	return result;
}