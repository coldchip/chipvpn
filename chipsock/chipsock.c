#include "chipsock.h"

CSHost *chip_host_create(CSAddress *addr, int peer_count) {
	signal(SIGPIPE, SIG_IGN);
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0) {
		return NULL;
	}

	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0){
		return NULL;
	}

	if(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0){
		return NULL;
	}

	if(addr) {
		struct sockaddr_in       addr_s;
		addr_s.sin_family      = AF_INET;
		addr_s.sin_addr.s_addr = addr->ip; 
		addr_s.sin_port        = addr->port;
		if(bind(sock, (struct sockaddr *)&addr_s, sizeof(addr_s)) != 0) { 
			return NULL;
		}
		if(listen(sock, 5) != 0) { 
			return NULL;
		}
	}

	CSHost *host = malloc(sizeof(CSHost));
	host->fd         = sock;
	host->fd2        = -1;
	host->is_host    = addr == NULL ? false : true;
	host->peer_count = peer_count;
	CSPeer *peers = malloc(sizeof(CSPeer) * peer_count);
	for(CSPeer *peer = peers; peer < &peers[peer_count]; ++peer) {
		peer->state = STATE_DISCONNECTED;
	}
    host->peers = peers;
    list_clear(&host->notify);
	return host;
}

CSPeer *chip_host_connect(CSHost *host, CSAddress *addr) {
	struct sockaddr_in       addr_s;
	addr_s.sin_family      = AF_INET;
	addr_s.sin_addr.s_addr = addr->ip; 
	addr_s.sin_port        = addr->port;

	CSPeer *peer = chip_peer_get_disconnected(host);
	if(peer) {
		if(connect(host->fd, (struct sockaddr*)&addr_s, sizeof(addr_s)) == 0) {
			chip_peer_update_ping(peer);
			peer->host       = host;
			peer->buffer_pos = 0;
			peer->fd = host->fd;
			peer->state = STATE_CONNECTED;

			CSNotification *notification = malloc(sizeof(CSNotification));
			notification->peer = peer;
			notification->type = EVENT_CONNECT;
			list_insert(list_end(&host->notify), notification);
			return peer;
		}
	}
	return NULL;
}

void chip_host_ping_service(CSHost *host) {
	if((chip_proto_get_time() - host->last_service_time) >= PING_INTERVAL) {
		for(CSPeer *peer = host->peers; peer < &host->peers[host->peer_count]; ++peer) {
			if(chip_peer_is_unpinged(peer)) {
				if(peer->state == STATE_CONNECTED) {
					chip_peer_disconnect(peer);
				}
			} else if(peer->state == STATE_CONNECTED) {
				chip_peer_ping(peer);
			}
		}
		host->last_service_time = chip_proto_get_time();
	}
}

int chip_host_notification_service(CSHost *host, CSEvent *event) {
	while(!list_empty(&host->notify)) {
		CSNotification *notification = (CSNotification*)list_remove(list_begin(&host->notify));

		event->peer = notification->peer;
		event->type = notification->type;
		free(notification);

		return 1;
	}

	return 0;
}

int chip_host_packet_dispatch_service(CSHost *host, CSEvent *event) {
	for(CSPeer *peer = host->peers; peer < &host->peers[host->peer_count]; ++peer) {
		if(peer->state & STATE_CONNECTED) {

			CSPacketHeader *header = (CSPacketHeader*)&peer->buffer;
			CSPacketType    type = ntohl(header->type);
			uint32_t        size = ntohl(header->size);
			char           *data = &peer->buffer[sizeof(CSPacketHeader)];

			if(
				peer->buffer_pos >= (size + sizeof(CSPacketHeader)) && 
				peer->buffer_pos >= sizeof(CSPacketHeader)
			) {
				peer->buffer_pos = 0;

				switch(type) {
					case PT_PING: {
						chip_peer_update_ping(peer);
					}
					break;
					case PT_DATA: {
						event->peer = peer;
						event->data = data;
						event->size = size;
						event->type = EVENT_RECEIVE;
						return 1;
					}
					break;
				}
			}
		}
	}
	return 0;
}

int chip_host_event(CSHost *host, CSEvent *event) {
	chip_host_ping_service(host);
	if(chip_host_notification_service(host, event) > 0) {
		return 1;
	}
	if(chip_host_packet_dispatch_service(host, event) > 0) {
		return 1;
	}

	int max = host->fd;

	FD_ZERO(&host->rdset);
	FD_SET(host->fd, &host->rdset);

	for(CSPeer *peer = host->peers; peer < &host->peers[host->peer_count]; ++peer) {
		if(peer->state == STATE_CONNECTED) {
			FD_SET(peer->fd, &host->rdset);
			if(peer->fd > max) {
				max = peer->fd;
			}
		}
	}

	if(host->fd2 != -1) {
		FD_SET(host->fd2, &host->rdset);
		if(host->fd2 > max) {
			max = host->fd2;
		}
	}

	struct timeval tv;
	tv.tv_sec  = 1;
	tv.tv_usec = 0;

	select(max + 1, &host->rdset, NULL, NULL, &tv);

	if(FD_ISSET(host->fd, &host->rdset) && host->is_host == true) {
		CSPeer *peer = chip_peer_get_disconnected(host);
		if(peer) {
			socklen_t len = sizeof(peer->addr);
			chip_peer_update_ping(peer);
			peer->host       = host;
			peer->buffer_pos = 0;
			peer->fd         = accept(host->fd, (struct sockaddr*)&peer->addr, &len);
			peer->state      = STATE_CONNECTED;

			event->peer = peer;
			event->type = EVENT_CONNECT;
			return 1;
		}
	}

	for(CSPeer *peer = host->peers; peer < &host->peers[host->peer_count]; ++peer) {
		if(peer->state == STATE_CONNECTED) {
			if(FD_ISSET(peer->fd, &host->rdset)) {
				CSPacketHeader *header = (CSPacketHeader*)&peer->buffer;

				uint32_t left = sizeof(CSPacketHeader) - peer->buffer_pos;

				if(peer->buffer_pos >= sizeof(CSPacketHeader)) {
					left += ntohl(header->size);
				}

				if((left + peer->buffer_pos) < sizeof(peer->buffer)) {
					int readed = recv(peer->fd, &peer->buffer[peer->buffer_pos], left, 0);
					if(readed > 0) {
						peer->buffer_pos += readed;
					} else {
						chip_peer_disconnect(peer);
					}
				} else {
					chip_peer_disconnect(peer);
				}
			}
		}
	}

	if(FD_ISSET(host->fd2, &host->rdset)) {
		event->peer = NULL;
		event->type = EVENT_SOCKET_SELECT;
		return 1;
	}

	event->type = EVENT_NONE;
	return 0;
}

void chip_host_select(CSHost *host, int fd) {
	host->fd2 = fd;
}

uint32_t chip_proto_get_time() {
	// Second precision
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000) / 1000;
}

void chip_host_free(CSHost *host) {
	for(CSPeer *peer = host->peers; peer < &host->peers[host->peer_count]; ++peer) {
		if(peer->state == STATE_CONNECTED) {
			close(peer->fd);
		}
	}
	close(host->fd);

	while(!list_empty(&host->notify)) {
		CSNotification *notification = (CSNotification*)list_remove(list_begin(&host->notify));
		free(notification);
	}

	free(host->peers);
	free(host);
}