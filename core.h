#include <stdbool.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <signal.h>
#include <netdb.h>
#include "encryption.h"
#include "chipvpn.h"
#include "tun.h"
#include "list.h"
#include "json/include/cJSON.h"

typedef struct _VPNPeer {
	ListNode node;
	int fd;
	bool is_authed;
	uint32_t last_ping;
	uint32_t internal_ip;

	uint64_t tx;
	uint64_t rx;

	int buffer_pos;
	char buffer[16384];
} VPNPeer;

typedef enum {
	VPN_TYPE_DATA,
	VPN_TYPE_ASSIGN,
	VPN_TYPE_AUTH,
	VPN_PING,
	VPN_PONG,
	VPN_TYPE_MSG
} VPNPacketType;

typedef struct _VPNAuthPacket {
	char data[8192];
} VPNAuthPacket;

typedef struct _VPNAssignPacket {
	uint32_t ip;
	uint32_t subnet;
	uint32_t gateway;
	uint32_t mtu;
} VPNAssignPacket;

typedef struct _VPNDataPacket {
	char data[8192];
} VPNDataPacket;

typedef struct _VPNPacketHeader {
	VPNPacketType type;
	int size;
} VPNPacketHeader;

typedef struct _VPNPacket {
	VPNPacketHeader header;
	union {
		VPNAuthPacket auth_packet;
		VPNAssignPacket dhcp_packet;
		VPNDataPacket data_packet;
	} data;
} VPNPacket;

void               chipvpn_event_loop(char *config);
void               chipvpn_socket_event(VPNPeer *peer, VPNPacket *packet);
void               chipvpn_tun_event(VPNDataPacket *packet, int size);
VPNPeer           *chipvpn_peer_alloc(int fd);
void               chipvpn_peer_dealloc(VPNPeer *peer);
void               chipvpn_peer_send(VPNPeer *peer, VPNPacketType type, void *data, int size);
uint32_t           chipvpn_get_peer_free_ip();
VPNPeer           *chipvpn_get_peer_by_ip(uint32_t ip);
uint32_t 		   chipvpn_get_time();