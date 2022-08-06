#ifndef SOCKET_H
#define SOCKET_H

#include "list.h"
#include "peer.h"
#include <stdbool.h>

typedef struct _VPNSocket {
	int fd;
	List peers;
} VPNSocket;

VPNSocket         *chipvpn_socket_create();
bool               chipvpn_socket_setopt_buffer(VPNSocket *socket, int send, int recv);
bool               chipvpn_socket_set_non_block(int fd);
bool               chipvpn_socket_bind(VPNSocket *host, const char *ip, int port);
VPNPeer           *chipvpn_socket_connect(VPNSocket *host, const char *ip, int port);
VPNPeer           *chipvpn_socket_accept(VPNSocket *host);
bool               chipvpn_socket_has_peer(VPNSocket *host, VPNPeer *peer);
void               chipvpn_socket_free(VPNSocket *host);

#endif