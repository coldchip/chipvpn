#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

typedef struct _IPPacket {
	uint8_t	version:4, ihl:4;
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
	uint32_t size;
} VPNPacketHeader;

typedef struct _VPNPacket {
	VPNPacketHeader header;
	union {
		VPNAuthPacket auth_packet;
		VPNAssignPacket dhcp_packet;
		VPNDataPacket data_packet;
	} data;
} VPNPacket;

#endif