/*
 * ColdChip ChipVPN
 *
 * Copyright (c) 2016-2021, Ryan Loh <ryan@chip.sg>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README for more details.
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <netinet/in.h>
#include "list.h"

#define CHIPVPN_MAX_PACKET_SIZE 4096

#define PACKED __attribute__((__packed__))

#define PLEN(packet)  ( vpnpacket_len(packet) )

typedef struct _IPPacket {
	uint8_t	version:4, ihl:4;
    uint8_t  ip_tos;                 /* type of service */
    uint16_t ip_len;                 /* total length */
    uint16_t ip_id;                  /* identification */
    uint16_t ip_off;                 /* fragment offset field */
    uint8_t  ip_ttl;                 /* time to live */
    uint8_t  ip_p;                   /* protocol */
    uint16_t ip_sum;                 /* checksum */
   	struct in_addr src_addr;   			/* Source IP address. */
    struct in_addr dst_addr;
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
	VPN_PACKET_OK = 1,
	VPN_EAGAIN = 0,
	VPN_CONNECTION_END = -1
} VPNPacketError;

typedef enum {
	VPN_FLAG_DATA = 0,
	VPN_FLAG_CONTROL = 1
} VPNPacketFlag;

typedef enum {
	VPN_TYPE_INIT = 0,
	VPN_TYPE_INIT_REPLY,
	VPN_TYPE_CERT,
	VPN_TYPE_CERT_REPLY,
	VPN_TYPE_KEY,
	VPN_TYPE_KEY_REPLY,
	VPN_TYPE_LOGIN,
	VPN_TYPE_LOGIN_REPLY,
	VPN_TYPE_ASSIGN,
	VPN_TYPE_ASSIGN_REPLY,
	VPN_TYPE_ROUTE,
	VPN_TYPE_ROUTE_REPLY,
	VPN_TYPE_DATA,
	VPN_TYPE_PING,
	VPN_TYPE_MSG
} VPNPacketType;

typedef struct PACKED _VPNInitPacket {
	uint32_t version;
	uint32_t protocol;
} VPNInitPacket;

typedef struct PACKED _VPNCertPacket {
	uint8_t cert[8192];
} VPNCertPacket;

typedef struct PACKED _VPNKeyPacket {
	uint8_t iv[16];
	uint8_t key[32];
} VPNKeyPacket;

typedef struct PACKED _VPNAuthPacket {
	uint8_t token[512];
} VPNAuthPacket;

typedef struct PACKED _VPNDHCPPacket {
	uint32_t ip;
	uint32_t subnet;
	uint32_t mtu;
} VPNDHCPPacket;

typedef struct PACKED _VPNRoutePacket {
	uint32_t src;
	uint32_t mask;
	uint32_t dst;
} VPNRoutePacket;

typedef struct PACKED _VPNDataPacket {
	uint8_t data[CHIPVPN_MAX_PACKET_SIZE];
} VPNDataPacket;

typedef struct PACKED _VPNMsgPacket {
	uint8_t message[CHIPVPN_MAX_PACKET_SIZE];
} VPNMsgPacket;

typedef struct PACKED _VPNPacketHeader {
	uint8_t type;
	uint16_t size;
} VPNPacketHeader;

typedef union _VPNPacketBody {
	VPNInitPacket init_packet;
	VPNCertPacket cert_packet;
	VPNKeyPacket key_packet;
	VPNAuthPacket auth_packet;
	VPNDHCPPacket dhcp_packet;
	VPNRoutePacket route_packet;
	VPNDataPacket data_packet;
	VPNMsgPacket msg_packet;
} VPNPacketBody;

typedef struct PACKED _VPNPacket {
	VPNPacketHeader header;
	VPNPacketBody data;
} VPNPacket;

int vpnpacket_len(VPNPacket *packet);

#endif