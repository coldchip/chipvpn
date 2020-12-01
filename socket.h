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
#include <time.h>
#include <unistd.h>
#include "list.h"

#define PING_INTERVAL 1

typedef struct _Socket {
	int fd;
	int queue_size;
	List frag_queue;
	List peers;
	uint32_t last_service_time;
	int peer_count;
} Socket;

typedef struct _Session {
	char data[16];
} Session;

typedef enum {
	RELIABLE,
	DATAGRAM
} SendType;

typedef enum {
	PT_ACK = (1 << 1),
	PT_CONNECT = (1 << 2),
	PT_CONNECT_VERIFY = (1 << 3),
	PT_PING = (1 << 4),
	PT_DATA = (1 << 5)
} PacketType;

typedef enum {
	EVENT_CONNECT,
	EVENT_RECEIVE,
	EVENT_DISCONNECT,
	EVENT_NONE
} EventType;

typedef enum {
	STATE_DISCONNECTING,
	STATE_DISCONNECTED,
	STATE_CONNECTED
} PeerState;

typedef struct _Peer {
	ListNode node;
	Socket *socket;
	PeerState state;
	uint32_t internal_ip;
	struct sockaddr_in addr;
	char key[64];
	int last_ping;
	uint64_t tx;
	uint64_t rx;
	uint64_t quota;
	Session session;
	uint32_t seqid;
	uint32_t ackid;
} Peer;

typedef struct _SocketEvent {
	EventType type;
	Peer *peer;
	char *data;
	int size;
} SocketEvent;

typedef struct _PacketHeader {
	PacketType type;
	int size;
	Session session;
	uint32_t seqid;
	uint32_t ackid;
} PacketHeader;

typedef struct _PacketData {
	char data[5000];
} PacketData;

typedef struct _Packet {
	PacketHeader header;
	PacketData   data;
} Packet;

typedef struct _FragmentHeader {
	int size;
	int count;
	int index;
	int id;
	int offset;
} FragmentHeader;

typedef struct _FragmentData {
	char data[10000];
} FragmentData;

typedef struct _Fragment {
	FragmentHeader header;
	FragmentData   data;
} Fragment;

typedef struct _FragmentEntry {
	ListNode node;
	uint32_t expiry;
	struct sockaddr_in addr;
	Fragment fragment;
} FragmentEntry;

Socket *new_socket(int peer_count);
bool socket_bind(Socket *socket, char *ip, int port);
void socket_connect(Socket *socket, char *ip, int port);
int get_socket_fd(Socket *socket);
int socket_event(Socket *socket, SocketEvent *event);

Peer *socket_handle_connect(Socket *socket, struct sockaddr_in addr);
Peer *socket_handle_verify_connect(Socket *socket, Session session, struct sockaddr_in addr);

void socket_send_fragment(Socket *socket, void *data, int size, struct sockaddr_in addr);
bool socket_recv_fragment(Socket *socket, void *data, int size, struct sockaddr_in *addr);

void frag_queue_insert(Socket *socket, Fragment fragment, struct sockaddr_in addr);
void frag_queue_remove(Socket *socket, uint32_t id);
void free_frag_entry(FragmentEntry *entry);

void socket_fill_random(char *buffer, int size);
void socket_free(Socket *socket);

// peer.c

void socket_peer_update_ping(Peer *peer);
bool socket_peer_is_unpinged(Peer *peer);
void socket_peer_ping(Peer *peer);
void socket_peer_send(Peer *peer, char *data, int size, SendType type);
Peer *socket_peer_get_by_session(Socket *socket, Session id);
void socket_peer_disconnect(Peer *peer);

uint32_t get_peer_free_ip(List *peers);
Peer *get_peer_by_ip(List *peers, uint32_t ip);

#endif