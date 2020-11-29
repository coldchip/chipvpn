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
#include "aes.h"

#define API extern

#define PING_INTERVAL 1

#define MAX_MTU 1500

#define DIM(x) (sizeof(x)/sizeof(*(x)))

// list.c

typedef struct _ListNode
{
   struct _ListNode * next;
   struct _ListNode * previous;
} ListNode;

typedef struct _List
{
   ListNode sentinel;
} List;

extern void list_clear (List *);

extern ListNode * list_insert (ListNode *, void *);
extern void * list_remove (ListNode *);
extern ListNode * list_move (ListNode *, void *, void *);

extern size_t list_size (List *);

#define list_begin(list) ((list) -> sentinel.next)
#define list_end(list) (& (list) -> sentinel)

#define list_empty(list) (list_begin (list) == list_end (list))

#define list_next(iterator) ((iterator) -> next)
#define list_previous(iterator) ((iterator) -> previous)

#define list_front(list) ((void *) (list) -> sentinel.next)
#define list_back(list) ((void *) (list) -> sentinel.previous)

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

typedef struct _Session {
	char data[16];
} Session;

typedef enum {
	RELIABLE,
	DATAGRAM
} SendType;

typedef enum {
	PT_CONNECT_SYN,
	PT_CONNECT_ACK,
	PT_PING,
	PT_DATA
} PacketType;

typedef enum {
	EVENT_CONNECT,
	EVENT_RECEIVE,
	EVENT_NONE
} EventType;

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

API char *read_string(FILE *file, char const *desired_name);
API bool read_bool(FILE *file, char const *desired_name);
API int read_int(FILE *file, char const *desired_name);
API char *read_file_into_buffer(char *file);
API void get_default_gateway(char *ip);
API int exec_sprintf(char *format, ...);
API void warning(char *format, ...);
API void error(char *format, ...);
API void console_log(char *format, ...);
API void fill_random(char *buffer, int size);
API char *format_size(uint64_t size);

// firewall.c

API bool validate_packet(char *stream);

// socket.c

typedef struct _Socket {
	int fd;
	int queue_size;
	List frag_queue;
	List peers;
} Socket;

typedef struct _Peer {
	ListNode node;
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

API Socket *new_socket();
API bool socket_bind(Socket *socket, char *ip, int port);
API void socket_connect(Socket *socket, char *ip, int port);
API int get_socket_fd(Socket *socket);
API void socket_service(Socket *socket);
API void socket_send(Socket *socket, Peer *peer, char *data, int size, SendType type);
API int socket_recv(Socket *socket, Peer **peer, char *data, int size, EventType *type);
API void socket_send_fragment(Socket *socket, void *data, int size, struct sockaddr_in addr);
API bool socket_recv_fragment(Socket *socket, void *data, int size, struct sockaddr_in *addr);
API void socket_free(Socket *socket);

void frag_queue_insert(Socket *socket, Fragment fragment, struct sockaddr_in addr);
void frag_queue_remove(Socket *socket, uint32_t id);
void free_frag_entry(FragmentEntry *entry);

// tun.c

typedef struct _Tun {
	char *dev;
	int fd;
} Tun;

API Tun *open_tun(char *dev);
API void setifip(Tun *tun, char* local, char* mask, int mtu);
API void ifup(Tun *tun);
API void free_tun(Tun *tun);

// encryption.c

API void encrypt(char *key, char *data, int length);
API void decrypt(char *key, char *data, int length);

// peer.c

API void update_ping(Peer *peer);
API bool is_unpinged(Peer *peer);
API uint32_t get_peer_free_ip(List *peers);
API Peer *get_peer_by_ip(List *peers, uint32_t ip);
API Peer *get_peer_by_session(List *peers, Session id);

// core.c

typedef enum {
	STATE_CONNECTING,
	STATE_CONNECTED,
	STATE_DISCONNECTED,
	STATE_ONLINE
} Status;

API void run_core(char *config);

void print_console(Status status, char *server_ip, char *server_port, bool is_server, uint64_t tx, uint64_t rx, int peers, char *dev);
void stop_core();



#ifdef __cplusplus
}
#endif

#endif