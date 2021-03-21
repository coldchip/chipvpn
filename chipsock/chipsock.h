#ifndef CHIPSOCKET
#define CHIPSOCKET

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h> 
#include <sys/syscall.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include "../list.h"

#define PING_INTERVAL 1

typedef struct _Socket {
	int fd;
	int fd2;
	fd_set rdset;
	struct _Peer *peers;
	int peer_count;
	int last_service_time;
	List notify;
} Socket;

typedef enum {
	RELIABLE,
	DATAGRAM
} SendType;

typedef enum {
	PT_DATA,
	PT_PING
} PacketType;

typedef enum {
	EVENT_CONNECT,
	EVENT_RECEIVE,
	EVENT_DISCONNECT,
	EVENT_SOCKET_SELECT,
	EVENT_NONE
} EventType;

typedef enum {
	STATE_DISCONNECTED,
	STATE_CONNECTED,
} PeerState;

typedef struct _Peer {
	Socket *host;
	int fd;
	int last_ping;
	PeerState state;
	struct sockaddr_in addr;
	char buffer[65535];
	int buffer_pos;
	void *data;
} Peer;

typedef struct _PacketHeader {
	PacketType type;
	int size;
	
} PacketHeader;

typedef struct _PacketData {
	char data[5000];
} PacketData;

typedef struct _Packet {
	PacketHeader header;
	PacketData   data;
} Packet;

typedef struct _SocketEvent {
	EventType type;
	Peer *peer;
	char *data;
	int size;
} SocketEvent;

typedef struct _ChipSockNotification {
	ListNode node;
	Peer *peer;
	EventType type;
} ChipSockNotification;

// chipsock.c

Socket   *chip_host_create(int peer_count);
bool      chip_host_bind(Socket *socket, char *ip, int port);
Peer     *chip_host_connect(Socket *socket, char *ip, int port);
int       chip_host_event(Socket *socket, SocketEvent *event);
void      chip_host_select(Socket *socket, int fd);
uint32_t  chip_proto_get_time();
void      chip_host_free(Socket *socket);

// peer.c

void      chip_peer_update_ping(Peer *peer);
bool      chip_peer_is_unpinged(Peer *peer);
void      chip_peer_ping(Peer *peer);
void      chip_peer_send(Peer *peer, char *data, int size, SendType type);
Peer     *chip_peer_get_by_session(Socket *socket, uint32_t session);
void      chip_peer_disconnect(Peer *peer);
Peer     *chip_peer_get_disconnected(Socket *socket);
int       chip_peer_count_connected(Socket *socket);

#endif