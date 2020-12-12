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
#include "../list.h"

#define PING_INTERVAL 1

typedef struct _Socket {
	int fd;
	int queue_size;
	List frag_queue;
	List ack_queue;
	struct _Peer *peers;
	uint32_t last_service_time;
	int peer_count;
} Socket;

typedef enum {
	RELIABLE,
	DATAGRAM
} SendType;

typedef enum {
	PT_ACK = (1 << 0),
	PT_ACK_REPLY = (1 << 1),
	PT_RETRANSMIT = (1 << 2),
	PT_CONNECT = (1 << 3),
	PT_CONNECT_VERIFY = (1 << 4),
	PT_PING = (1 << 5),
	PT_DATA = (1 << 6)
} PacketType;

typedef enum {
	EVENT_CONNECT,
	EVENT_RECEIVE,
	EVENT_DISCONNECT,
	EVENT_CONNECT_TIMEOUT,
	EVENT_NONE
} EventType;

typedef enum {
	STATE_DISCONNECTING,
	STATE_DISCONNECTED,
	STATE_CONNECTED,
	STATE_CONNECTING
} PeerState;

typedef struct _Peer {
	Socket *socket;
	PeerState state;
	struct sockaddr_in addr;
	int last_ping;
	uint32_t session;
	uint32_t outgoing_seqid;
	uint32_t incoming_seqid;
	List ack_queue;
	void *data; // Custom Data
} Peer;

typedef struct _PacketHeader {
	PacketType type;
	int size;
	uint32_t session;
	uint32_t seqid;
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

typedef struct _ACKEntry {
	ListNode node;
	uint32_t seqid;
	char* packet;
	int size;
} ACKEntry;

typedef struct _SocketEvent {
	EventType type;
	Peer *peer;
	char *data;
	int size;
} SocketEvent;

Peer     *chip_proto_handle_connect(Socket *socket, uint32_t session, struct sockaddr_in addr);
bool      chip_proto_handle_verify_connect(Socket *socket, Peer *peer);
void      chip_proto_send_fragment(Socket *socket, void *data, int size, struct sockaddr_in addr);
bool      chip_proto_recv_fragment(Socket *socket, void *data, int size, struct sockaddr_in *addr);
void      chip_proto_insert_frag(Socket *socket, Fragment fragment, struct sockaddr_in addr);
void      chip_proto_remove_frag(Socket *socket, uint32_t id);
void      chip_proto_free_frag(FragmentEntry *entry);
uint32_t  chip_proto_get_time();

// host.c

Socket   *chip_host_create(int peer_count);
bool      chip_host_bind(Socket *socket, char *ip, int port);
Peer     *chip_host_connect(Socket *socket, char *ip, int port);
int       chip_host_event(Socket *socket, SocketEvent *event);
int       chip_host_get_fd(Socket *socket);
void      chip_host_free(Socket *socket);

// peer.c

void      chip_peer_update_ping(Peer *peer);
bool      chip_peer_is_unpinged(Peer *peer);
void      chip_peer_ping(Peer *peer);
void      chip_peer_send(Peer *peer, char *data, int size, SendType type);
void      chip_peer_send_outgoing_command(Peer *peer, PacketHeader *header, char *data, int size);
void      chip_peer_insert_ack(Peer *peer, uint32_t seqid, char *packet, int size);
ACKEntry *chip_peer_get_ack(Peer *peer, uint32_t seqid);
void      chip_peer_remove_ack(Peer *peer, uint32_t seqid);
void      chip_peer_free_ack(ACKEntry *entry);
Peer     *chip_peer_get_by_session(Socket *socket, uint32_t session);
void      chip_peer_disconnect(Peer *peer);
Peer     *chip_peer_get_disconnected(Socket *socket);
int       chip_peer_count_connected(Socket *socket);

#endif