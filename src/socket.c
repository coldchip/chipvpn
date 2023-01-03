#include "socket.h"
#include "peer.h"
#include "chipvpn.h"
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <netinet/tcp.h>

VPNSocket *chipvpn_socket_create() {
	VPNSocket *host = malloc(sizeof(VPNSocket));

	list_clear(&host->peers);

	int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

	if(!chipvpn_socket_set_non_block(fd)) {
		return NULL;
	}

	if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(char){1}, sizeof(int)) < 0){
		return NULL;
	}
	if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &(char){1}, sizeof(int)) < 0){
		return NULL;
	}

	host->fd = fd;

	return host;
}

bool chipvpn_socket_setopt_buffer(VPNSocket *socket, int send, int recv) {
	if(setsockopt(socket->fd, SOL_SOCKET, SO_SNDBUF, (char*)&send, (int)sizeof(send)) < 0){
		return false;
	}
	if(setsockopt(socket->fd, SOL_SOCKET, SO_RCVBUF, (char*)&recv, (int)sizeof(recv)) < 0){
		return false;
	}
	return true;
}

bool chipvpn_socket_set_non_block(int fd) {
	int flags = fcntl(fd, F_GETFL);
	if(flags == -1) {
		return false;
	}

	if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0) {
		return true;
	}

	return false;
}

bool chipvpn_socket_bind(VPNSocket *host, const char *ip, int port) {
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip); 
	addr.sin_port        = htons(port);

	if(bind(host->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { 
		return false;
	}

	if(listen(host->fd, 32) != 0) { 
		return false;
	}
	return true;
}

VPNPeer *chipvpn_socket_connect(VPNSocket *host, const char *ip, int port) {
	struct sockaddr_in     addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip); 
	addr.sin_port        = htons(port);

	int connect_start = chipvpn_get_time();
	while(true) {
		if(connect(host->fd, (struct sockaddr *)&addr, sizeof(addr)) != -1) {
			break;
		}
		if(chipvpn_get_time() - connect_start > 5) {
			return NULL;
		}
	}

	VPNPeer *peer = chipvpn_peer_create(host->fd);
	list_insert(list_end(&host->peers), peer);

	return peer;
}

VPNPeer *chipvpn_socket_accept(VPNSocket *host) {
	struct sockaddr_in addr;

	int fd = accept(host->fd, (struct sockaddr*)&addr, &(socklen_t){sizeof(addr)});
	if(fd >= 0) {
		if(!chipvpn_socket_set_non_block(fd)) {
			chipvpn_error("unable to set socket to non blocking mode");
		}

		VPNPeer *peer = chipvpn_peer_create(fd);
		list_insert(list_end(&host->peers), peer);

		return peer;
	}
	return NULL;
}

void chipvpn_socket_free(VPNSocket *host) {
	ListNode *i = list_begin(&host->peers);
	while(i != list_end(&host->peers)) {
		VPNPeer *peer = (VPNPeer*)i;
		i = list_next(i);
		chipvpn_peer_disconnect(peer);
	}

	close(host->fd);

	free(host);
}