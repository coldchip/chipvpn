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
		header.type = htonl(PT_PING);
		header.size = htonl(0);

		write(peer->fd, &header, sizeof(header));
	}
}

void chip_peer_send(Peer *peer, char *data, int size, SendType type) {
	if(peer->state == STATE_CONNECTED) {
		PacketHeader header;
		header.type = htonl(PT_DATA);
		header.size = htonl(size);

		char packet[sizeof(PacketHeader) + size];

		memcpy(packet, (char*)&header, sizeof(PacketHeader));
		memcpy(packet + sizeof(PacketHeader), data, size);
		write(peer->fd, packet, sizeof(packet));
	}
}

void chip_peer_disconnect(Peer *peer) {
	// send_peer: Packet sequencing and reliability layer
	// Packet fragmentation will be handled in socket_send_fragment
	if(peer->state == STATE_CONNECTED) {

		peer->state = STATE_DISCONNECTED;

		ChipSockNotification *notification = malloc(sizeof(ChipSockNotification));
		notification->peer = peer;
		notification->type = EVENT_DISCONNECT;
		list_insert(list_end(&peer->host->notify), notification);

		close(peer->fd);
	}
}

Peer *chip_peer_get_disconnected(Socket *socket) {
	for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
		if(peer->state == STATE_DISCONNECTED) {
			return peer;
		}
	}
	return NULL;
}