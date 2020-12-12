#include "chipsock.h"

void chip_peer_update_ping(Peer *peer) {
	if(peer) {
		peer->last_ping = chip_proto_get_time(NULL);
	}
}

bool chip_peer_is_unpinged(Peer *peer) {
	if(peer) {
		return (chip_proto_get_time(NULL) - peer->last_ping) >= 10;
	}
	return true;
}

void chip_peer_ping(Peer *peer) {
	if(peer->state == STATE_CONNECTED) {
		PacketHeader header;
		header.type = PT_PING | PT_ACK;
		chip_peer_send_outgoing_command(peer, &header, NULL, 0);
	}
}

void chip_peer_send(Peer *peer, char *data, int size, SendType type) {
	// send_peer: Packet sequencing and reliability layer
	// Packet fragmentation will be handled in socket_send_fragment
	if(peer->state == STATE_CONNECTED) {
		PacketHeader header;
		header.type = PT_DATA;
		if(type == RELIABLE) {
			header.type |= PT_ACK;
		}

		chip_peer_send_outgoing_command(peer, &header, data, size);
	}
}

void chip_peer_send_outgoing_command(Peer *peer, PacketHeader *header, char *data, int size) {
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
				chip_peer_insert_ack(peer, peer->outgoing_seqid, (char*)&packet, sizeof(PacketHeader) + size);
				peer->outgoing_seqid++;
			}
		}
		chip_proto_send_fragment(peer->socket, (char*)&packet, sizeof(PacketHeader) + size, peer->addr);
	}
}

void chip_peer_insert_ack(Peer *peer, uint32_t seqid, char *packet, int size) {
	if(peer->state != STATE_DISCONNECTED) {
		ACKEntry *entry = malloc(sizeof(ACKEntry));
		entry->seqid  = seqid;
		entry->packet = malloc(sizeof(char) * size);
		entry->size   = size;
		memcpy(entry->packet, packet, size);
		list_insert(list_end(&peer->ack_queue), entry);
		
		if(list_size(&peer->ack_queue) > 500) {
			chip_peer_disconnect(peer);
		}
	}
}

ACKEntry *chip_peer_get_ack(Peer *peer, uint32_t seqid) {
	if(peer->state != STATE_DISCONNECTED) {
		ListNode *x = list_begin(&peer->ack_queue);
		while(x != list_end(&peer->ack_queue)) {
			ACKEntry *entry = (ACKEntry*)x;
			x = list_next(x);
			if(entry->seqid == seqid) {
				return entry;
			}
		}
	}
	return NULL;
}

void chip_peer_remove_ack(Peer *peer, uint32_t seqid) {
	if(peer->state != STATE_DISCONNECTED) {
		ListNode *i = list_begin(&peer->ack_queue);

		while(i != list_end(&peer->ack_queue)) {
			ACKEntry *entry = (ACKEntry*)i;
			i = list_next(i);
			if(entry->seqid <= seqid) {
				chip_peer_free_ack(entry);
			}
		}
	}
}

void chip_peer_free_ack(ACKEntry *entry) {
	list_remove(&entry->node);
	free(entry->packet);
	free(entry);
}

Peer *chip_peer_get_by_session(Socket *socket, uint32_t session) {
	for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
		if(peer->state != STATE_DISCONNECTED) {
			if(peer->session == session) {
				return peer;
			}
		}
	}
	return NULL;
}

void chip_peer_disconnect(Peer *peer) {
	// queue for disconnection
	peer->state = STATE_DISCONNECTING;
}

Peer *chip_peer_get_disconnected(Socket *socket) {
	for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
		if(peer->state == STATE_DISCONNECTED) {
			return peer;
		}
	}
	return NULL;
}

int chip_peer_count_connected(Socket *socket) {
	int result = 0;
	for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
		if(peer->state == STATE_CONNECTED) {
			result++;
		}
	}
	return result;
}