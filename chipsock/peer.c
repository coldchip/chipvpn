#include "chipsock.h"

void chip_peer_update_ping(CSPeer *peer) {
	if(peer) {
		peer->last_ping = chip_proto_get_time(NULL); 
	}
}

bool chip_peer_is_unpinged(CSPeer *peer) {
	if(peer) {
		return (chip_proto_get_time(NULL) - peer->last_ping) >= 10;
	}
	return true;
}

void chip_peer_ping(CSPeer *peer) {
	if(peer->state == STATE_CONNECTED) {
		CSPacketHeader header;
		header.type = htonl(PT_PING);
		header.size = htonl(0);

		if(write(peer->fd, &header, sizeof(header)) <= 0) {
			chip_peer_disconnect(peer);
		}
	}
}

void chip_peer_send(CSPeer *peer, char *data, int size) {
	if(peer->state == STATE_CONNECTED) {
		CSPacketHeader header;
		header.type = htonl(PT_DATA);
		header.size = htonl(size);
		strcpy(header.identifier, "CHIPSOCKET/1.1");

		char packet[sizeof(CSPacketHeader) + size];
		memcpy(packet, (char*)&header, sizeof(CSPacketHeader));
		memcpy(packet + sizeof(CSPacketHeader), data, size);
		
		if(write(peer->fd, &packet, sizeof(packet)) <= 0) {
			chip_peer_disconnect(peer);
		}
	}
}

void chip_peer_disconnect(CSPeer *peer) {
	if(peer->state == STATE_CONNECTED) {

		peer->state = STATE_DISCONNECTED;

		CSNotification *notification = malloc(sizeof(CSNotification));
		notification->peer           = peer;
		notification->type           = EVENT_DISCONNECT;
		list_insert(list_end(&peer->host->notify), notification);

		close(peer->fd);
	}
}

CSPeer *chip_peer_get_disconnected(CSHost *host) {
	for(CSPeer *peer = host->peers; peer < &host->peers[host->peer_count]; ++peer) {
		if(peer->state == STATE_DISCONNECTED) {
			return peer;
		}
	}
	return NULL;
}