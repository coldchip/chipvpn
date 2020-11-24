#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include "chipvpn.h"

Socket *new_socket() {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		return NULL;
	}
	Socket *socket = malloc(sizeof(Socket));
	socket->fd = sock;
	socket->frag_queue = new_queue(50);
	return socket;
}

bool socket_bind(Socket *socket, struct sockaddr_in addr) {
	if(bind(socket->fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) { 
		return true;
	}
	return false;
}

int get_socket_fd(Socket *socket) {
	return socket->fd;
}

void socket_service(Socket *socket) {
	queue_service(socket->frag_queue);
}

void send_peer(Socket *socket, int seqid, void *data, int size, struct sockaddr_in *addr, SendType type) {
	Fragment fragment;
	int mss    = 400;
	int pieces = floor(size / mss);
	int id     = rand();

	for(int i = 0; i <= pieces; i++) {
		int offset = i * mss;
		int frag_size  = i == pieces ? size - offset : mss;
		fragment.header.index    = htonl(i);
		fragment.header.count    = htonl(pieces);
		fragment.header.size     = htonl(frag_size);
		fragment.header.id       = htonl(id);
		fragment.header.offset   = htonl(i * mss);
		memcpy((char*)&fragment.data, data + offset, frag_size);

		if(sendto(socket->fd, (char*)&fragment, sizeof(FragmentHeader) + frag_size, MSG_CONFIRM, (struct sockaddr *)addr, sizeof(struct sockaddr)) != sizeof(Fragment)) {
			//printf("send_peer error\n");
		}
	}
}

bool recv_peer(Socket *socket, void *data, int size, struct sockaddr_in *addr) {
	socklen_t len = sizeof(struct sockaddr_in);

	Fragment fragment;

	if(recvfrom(socket->fd, (char*)&fragment, sizeof(Fragment), MSG_WAITALL, (struct sockaddr *)addr, &len) > 0) {
		int id        = ntohl(fragment.header.id);
		int max       = ntohl(fragment.header.count);
		int offset    = ntohl(fragment.header.offset);
		int frag_size = ntohl(fragment.header.size);

		queue_insert(socket->frag_queue, id, (char*)&(fragment.data), offset, frag_size, max);
	}

	if(queue_ready(socket->frag_queue, data, size) > 0) {
		return true;
	}

	return false;
}

void socket_free(Socket *socket) {
	close(socket->fd);
	free(socket);
}