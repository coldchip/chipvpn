#ifndef CHIPVPN
#define CHIPVPN

#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <stdint.h>
#include "aes.h"

#define API extern

#define PING_INTERVAL 1

#define MAX_MTU 1500

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

typedef struct IPPacket_ {
    uint8_t  ip_vhl;                 /* version << 4 | header length >> 2 */
    uint8_t  ip_tos;                 /* type of service */
    uint16_t ip_len;                 /* total length */
    uint16_t ip_id;                  /* identification */
    uint16_t ip_off;                 /* fragment offset field */
    #define IP_RF 0x8000             /* reserved fragment flag */
    #define IP_DF 0x4000             /* dont fragment flag */
    #define IP_MF 0x2000             /* more fragments flag */
    #define IP_OFFMASK 0x1FFF        /* mask for fragmenting bits */
    uint8_t  ip_ttl;                 /* time to live */
    uint8_t  ip_p;                   /* protocol */
    uint16_t ip_sum;                 /* checksum */
    struct  in_addr ip_src, ip_dst;  /* source and dest address */
} IPPacket;

typedef enum {
	CONNECT,
	DATA,
	PING,
	LOGIN_FAILED,
	CONNECTION_REJECTED
} PacketType;

typedef struct _PacketHeader {
	PacketType type;
	int size;
	char session[16];
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

// socket.c

typedef struct _Socket {
	int fd;
	List defrag_queue;
	List tx_queue;
} Socket;

typedef enum {
	RELIABLE,
	DATAGRAM,
	ACK
} SendType;

typedef struct _FragmentHeader {
	int fragment;
	int size;
	int offset;
	int id;
	int seqid;
	int max_frag;
	SendType type;
} FragmentHeader;

typedef struct _FragmentData {
	char data[5000];
} FragmentData;

typedef struct _Fragment {
	FragmentHeader header;
	FragmentData   data;
} Fragment;

typedef struct _FragmentQueue {
	ListNode node;
	Fragment packet;
} FragmentQueue;

typedef struct _ReceiptQueue {
	ListNode node;
	int seqid;
	struct sockaddr_in addr;
	int size;
	char *data;
	int time;
} ReceiptQueue;

void remove_receipt_from_queue(List *queue, int to_remove);
void remove_id_from_queue(List *queue, int to_remove);

API void socket_service(Socket *socket);
API void send_peer(Socket *socket, int seqid, void *data, int size, struct sockaddr_in *addr, SendType type);
API bool recv_peer(Socket *socket, void *data, int size, struct sockaddr_in *addr);

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

uint8_t get_sbox(uint8_t num);
uint8_t get_rsbox(uint8_t num);
API void encrypt(char *data, int length);
API void decrypt(char *data, int length);

// peer.c

typedef enum {
	CONNECTED,
	DISCONNECTED
} PeerState;

typedef struct _Peers {
	struct _Peer *peers;
	int peerCount;
} Peers;

typedef struct _Peer {
	char session[16];
	uint32_t internal_ip;
	struct sockaddr_in addr;
	PeerState state;
	int last_ping;
	uint64_t tx;
	uint64_t rx;
	uint64_t quota;
} Peer;

API Peers *new_peer_container(int peerCount);
API void free_peer_container(Peers *peers);
API void update_ping(Peer *peer);
API bool is_unpinged(Peer *peer);
API Peer *get_disconnected_peer(Peers *peers);
API uint32_t get_peer_free_ip(Peers *peers);
API Peer *get_peer_by_ip(Peers *peers, uint32_t ip);
API Peer *get_peer_by_session(Peers *peers, char *session);
API bool is_connected(Peer *peer);
API bool is_disconnected(Peer *peer);

// client.c

API void init_client();
void run_client(Tun *tun);
void stop_client();

// server.c

API void init_server();
void run_server(Tun *tun);
void fill_random(char *buffer, int size);
void stop_server();


#endif