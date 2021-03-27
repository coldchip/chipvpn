#ifndef CHIPVPN
#define CHIPVPN

#ifdef __cplusplus
extern "C"
{
#endif

#include <asm/byteorder.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <math.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<netdb.h>
#include "chipsock/chipsock.h"
#include "list.h"

#define MAX_MTU 1500

#define DIM(x) (sizeof(x)/sizeof(*(x)))

// chipvpn.c

#define max(a,b) \
({ __typeof__ (a) _a = (a); \
__typeof__ (b) _b = (b); \
_a > _b ? _a : _b; })

typedef struct _IPPacket {
    #if defined(__LITTLE_ENDIAN_BITFIELD)
		uint8_t	ihl:4,
				version:4;
	#elif defined (__BIG_ENDIAN_BITFIELD)
		uint8_t	version:4,
				ihl:4;
	#endif                 /* version << 4 | header length >> 2 */
    uint8_t  ip_tos;                 /* type of service */
    uint16_t ip_len;                 /* total length */
    uint16_t ip_id;                  /* identification */
    uint16_t ip_off;                 /* fragment offset field */
    uint8_t  ip_ttl;                 /* time to live */
    uint8_t  ip_p;                   /* protocol */
    uint16_t ip_sum;                 /* checksum */
   	uint32_t src_addr;   			/* Source IP address. */
    uint32_t dst_addr;
} IPPacket;

typedef struct _TCPHeader {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint8_t  data_offset;
	uint8_t  flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_p;
} TCPHeader;

typedef struct _UDPHeader {
	uint16_t src_port;		/* source port */
	uint16_t dst_port;		/* destination port */
	uint16_t length;		/* udp length */
	uint16_t checksum;		/* udp checksum */
} UDPHeader;

typedef struct _ICMPHeader {
	uint8_t type;		/* message type */
	uint8_t code;		/* type sub-code */
	uint16_t checksum;
	union {
		struct {
			uint16_t id;
			uint16_t sequence;
		} echo;			/* echo datagram */
		uint32_t gateway;	/* gateway address */
		struct {
			uint16_t __unused;
			uint16_t mtu;
		} frag;			/* path mtu discovery */
	} un;
} ICMPHeader;

char *read_string(FILE *file, char const *desired_name);
bool read_bool(FILE *file, char const *desired_name);
int read_int(FILE *file, char const *desired_name);
char *read_file_into_buffer(char *file);
uint32_t get_default_gateway();
int exec_sprintf(char *format, ...);
void warning(char *format, ...);
void error(char *format, ...);
void console_log(char *format, ...);
char *format_size(uint64_t size);

// firewall.c

bool validate_packet(char *stream);

// tun.c

typedef struct _Tun {
	char *dev;
	int fd;
} Tun;

Tun *open_tun(char *dev);
void setifip(Tun *tun, uint32_t ip, uint32_t mask, int mtu);
void ifup(Tun *tun);
void free_tun(Tun *tun);

// core.c

typedef struct _VPNPeer {
	bool is_authed;
	uint32_t uid;
	uint32_t internal_ip;
	uint64_t tx;
	uint64_t rx;
} VPNPeer;

typedef enum {
	VPN_TYPE_DATA,
	VPN_TYPE_ASSIGN,
	VPN_TYPE_AUTH
} VPNPacketType;

typedef struct _VPNAuthPacket {
	char token[128];
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

typedef struct _VPNPacket {
	struct {
		VPNPacketType type;
		uint32_t size;
	} header;
	union {
		VPNAuthPacket   p_auth;
		VPNAssignPacket p_assign;
		VPNDataPacket   p_data;
	} data;
} VPNPacket;

void               chipvpn_event_loop(char *config);
void               chipvpn_peer_send(CSPeer *peer, VPNPacketType type, void *data, int size);
uint32_t           chipvpn_get_peer_free_ip(CSHost *socket);
CSPeer            *chipvpn_get_peer_by_ip(CSHost *socket, uint32_t ip);
CSPeer            *chipvpn_get_peer_by_uid(CSHost *host, uint32_t uid);
static const char *chipvpn_bytes_pretty_print(uint64_t bytes);
unsigned int       chipvpn_crc32b(unsigned char *message, int size);

#ifdef __cplusplus
}
#endif

#endif