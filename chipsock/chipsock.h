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

typedef struct _CSAddress {
	uint32_t ip;
	uint16_t port;
} CSAddress;

typedef struct _CSHost {
	int fd;
	int fd2;
	bool is_host;
	fd_set rdset;
	struct _CSPeer *peers;
	int peer_count;
	int last_service_time;
	List notify;
} CSHost;

typedef enum {
	PT_DATA,
	PT_PING
} CSPacketType;

typedef enum {
	EVENT_CONNECT,
	EVENT_RECEIVE,
	EVENT_DISCONNECT,
	EVENT_SOCKET_SELECT,
	EVENT_NONE
} CSEventType;

typedef enum {
	STATE_DISCONNECTED,
	STATE_CONNECTED,
} CSPeerState;

typedef struct _CSPeer {
	CSHost *host;
	int fd;
	int last_ping;
	CSPeerState state;
	struct sockaddr_in addr;
	char buffer[65535];
	uint32_t buffer_pos;
	void *data;
} CSPeer;

typedef struct _CSPacketHeader {
	CSPacketType type;
	int size;
	char identifier[16];
} CSPacketHeader;

typedef struct _CSEvent {
	CSEventType type;
	CSPeer *peer;
	char *data;
	int size;
} CSEvent;

typedef struct _CSNotification {
	ListNode node;
	CSPeer *peer;
	CSEventType type;
} CSNotification;

// chipsock.c

CSHost   *chip_host_create(CSAddress *addr, int peer_count);
CSPeer   *chip_host_connect(CSHost *host, CSAddress *addr);
int       chip_host_ping_service(CSHost *host);
int       chip_host_notification_service(CSHost *host, CSEvent *event);
int       chip_host_packet_dispatch_service(CSHost *host, CSEvent *event);
int       chip_host_event(CSHost *host, CSEvent *event);
void      chip_host_select(CSHost *host, int fd);
uint32_t  chip_proto_get_time();
void      chip_host_free(CSHost *host);

// peer.c

void      chip_peer_update_ping(CSPeer *peer);
bool      chip_peer_is_unpinged(CSPeer *peer);
void      chip_peer_ping(CSPeer *peer);
void      chip_peer_send(CSPeer *peer, char *data, int size);
CSPeer   *chip_peer_get_by_session(CSHost *host, uint32_t session);
void      chip_peer_disconnect(CSPeer *peer);
CSPeer   *chip_peer_get_disconnected(CSHost *host);
int       chip_peer_count_connected(CSHost *host);

// encryption.c

void      chip_encrypt_buf(char *data, int length);
void      chip_decrypt_buf(char *data, int length);

#endif