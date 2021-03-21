#include "chipsock.h"

Socket *chip_host_create(int peer_count) {
	signal(SIGPIPE, SIG_IGN);
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0) {
		return NULL;
	}

	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0){
		return NULL;
	}

	Socket *socket = malloc(sizeof(Socket));
	socket->fd         = sock;
	socket->fd2        = -1;
	socket->peer_count = peer_count;
	Peer *peers = malloc(sizeof(Peer) * peer_count);
	for(Peer *peer = peers; peer < &peers[peer_count]; ++peer) {
		peer->state = STATE_DISCONNECTED;
	}
    socket->peers = peers;
    list_clear(&socket->notify);
	return socket;
}

bool chip_host_bind(Socket *socket, char *ip, int port) {
	struct sockaddr_in     addr;
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip); 
	addr.sin_port        = htons(port);

	printf("%s %i\n", ip, port);

	if(bind(socket->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { 
		return false;
	}

	if(listen(socket->fd, 5) != 0) { 
        return false;
    } 

	return true;
}

Peer *chip_host_connect(Socket *socket, char *ip, int port) {
	struct sockaddr_in     addr;
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip); 
	addr.sin_port        = htons(port);

	Peer *peer = chip_peer_get_disconnected(socket);
	if(peer) {
		if(connect(socket->fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
			chip_peer_update_ping(peer);
			peer->host       = socket;
			peer->buffer_pos = 0;
			peer->fd = socket->fd;
			peer->state = STATE_CONNECTED;

			ChipSockNotification *notification = malloc(sizeof(ChipSockNotification));
			notification->peer = peer;
			notification->type = EVENT_CONNECT;
			list_insert(list_end(&socket->notify), notification);
			return peer;
		}
	}
	return NULL;
}

int chip_host_service(Socket *socket) {
	if((chip_proto_get_time() - socket->last_service_time) >= PING_INTERVAL) {
		for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
			if(chip_peer_is_unpinged(peer)) {
				if(peer->state == STATE_CONNECTED) {
					chip_peer_disconnect(peer);
				}
			} else if(peer->state == STATE_CONNECTED) {
				chip_peer_ping(peer);
			}
		}
		socket->last_service_time = chip_proto_get_time();
	}
}

int chip_host_event(Socket *socket, SocketEvent *event) {
	chip_host_service(socket);

	while(!list_empty(&socket->notify)) {
		ChipSockNotification *notification = (ChipSockNotification*)list_remove(list_begin(&socket->notify));

		event->peer = notification->peer;
		event->type = notification->type;
		free(notification);

		return 1;
	}

	int max = socket->fd;

	FD_ZERO(&socket->rdset);

	FD_SET(socket->fd, &socket->rdset);

	for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
		if(peer->state == STATE_CONNECTED) {
			FD_SET(peer->fd, &socket->rdset);
			if(peer->fd > max) {
				max = peer->fd;
			}
		}
	}

	if(socket->fd2 != -1) {
		FD_SET(socket->fd2, &socket->rdset);
		if(socket->fd2 > max) {
			max = socket->fd2;
		}
	}

	struct timeval tv;
	tv.tv_sec  = 1;
	tv.tv_usec = 0;

	select(max + 1, &socket->rdset, NULL, NULL, &tv);

	if(FD_ISSET(socket->fd, &socket->rdset) && socket->peer_count > 1) {
		Peer *peer = chip_peer_get_disconnected(socket);
		if(peer) {
			socklen_t len = sizeof(peer->addr);
			chip_peer_update_ping(peer);
			peer->host  = socket;
			peer->fd    = accept(socket->fd, (struct sockaddr*)&peer->addr, &len);
			peer->state = STATE_CONNECTED;

			event->peer = peer;
			event->type = EVENT_CONNECT;
			return 1;
		}
	}

	for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
		if(peer->state == STATE_CONNECTED) {
			if(FD_ISSET(peer->fd, &socket->rdset)) {
				PacketHeader *header = (PacketHeader*)&peer->buffer;

				int left = 0;

				if(peer->buffer_pos < sizeof(PacketHeader)) {
					left = sizeof(PacketHeader) - peer->buffer_pos;
				} else {
					left = ntohl(header->size) + sizeof(PacketHeader) - peer->buffer_pos;
				}

				int readed = read(peer->fd, ((char*)&peer->buffer) + peer->buffer_pos, left);
				if(readed < 1) {
					chip_peer_disconnect(peer);
					break;
				} else {
					peer->buffer_pos += readed;
					if(peer->buffer_pos >= ntohl(header->size) + sizeof(PacketHeader) && peer->buffer_pos >= sizeof(PacketHeader)) {
						if(ntohl(header->type) == PT_PING) {
							peer->buffer_pos = 0;
							chip_peer_update_ping(peer);
						}
						if(ntohl(header->type) == PT_DATA) {
							peer->buffer_pos = 0;
							event->peer = peer;
							event->data = ((char*)&peer->buffer) + sizeof(PacketHeader);
							event->size = ntohl(header->size);
							event->type = EVENT_RECEIVE;
							return 1;
						}
					}
				}
			}
		}
	}

	if(FD_ISSET(socket->fd2, &socket->rdset)) {
		event->peer = NULL;
		event->type = EVENT_SOCKET_SELECT;
		return 1;
	}

	event->type = EVENT_NONE;
	return 0;
}

void chip_host_select(Socket *socket, int fd) {
	socket->fd2 = fd;
}

uint32_t chip_proto_get_time() {
	// Second precision
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000) / 1000;
}

void chip_host_free(Socket *socket) {
	close(socket->fd);
	free(socket);
}