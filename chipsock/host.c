#include "chipsock.h"

Socket *chip_host_create(int peer_count) {
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
	Peer *peers = malloc(sizeof(Peer) * peer_count);
	for(Peer *peer = peers; peer < &peers[peer_count]; ++peer) {
		peer->state = STATE_DISCONNECTED;
	}
    socket->peers = peers;
	return socket;
}

bool chip_host_bind(Socket *socket, char *ip, int port) {
	struct sockaddr_in     addr;
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip); 
	addr.sin_port        = htons(port);

	if(bind(socket->fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) { 
		return true;
	}
	return false;
}

Peer *chip_host_connect(Socket *socket, char *ip, int port) {
	struct sockaddr_in     addr;
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip); 
	addr.sin_port        = htons(port);

	Peer *peer = chip_peer_get_disconnected(socket);
	if(peer) {
		peer->socket         = socket;
		peer->state          = STATE_CONNECTING;
		peer->addr           = addr;
		peer->incoming_seqid = 0;
		peer->outgoing_seqid = 0;
		peer->session        = rand();
		list_clear(&peer->ack_queue);
		chip_peer_update_ping(peer);

		PacketHeader header;
		header.type = PT_CONNECT | PT_ACK;

		chip_peer_send_outgoing_command(peer, &header, NULL, 0);
		return peer;
	}
	return NULL;
}

int chip_host_get_fd(Socket *socket) {
	return socket->fd;
}

void chip_host_free(Socket *socket) {
	close(socket->fd);
	free(socket);
}