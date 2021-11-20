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
int                chipvpn_socket_set_non_block(int fd);
bool               chipvpn_socket_bind(VPNSocket *host, char *ip, int port);
VPNPeer           *chipvpn_socket_connect(VPNSocket *host, char *ip, int port);
VPNPeer           *chipvpn_socket_accept(VPNSocket *host);
void               chipvpn_socket_free(VPNSocket *host);

#endif