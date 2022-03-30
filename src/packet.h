/*
 * ColdChip ChipVPN
 *
 * Copyright (c) 2016-2021, Ryan Loh <ryan@coldchip.ru>
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
	VPN_HAS_DATA = 1,
	VPN_EAGAIN = 0,
	VPN_CONNECTION_END = -1
} VPNPacketError;

typedef enum {
	VPN_TYPE_SET_KEY = 0,
	VPN_TYPE_LOGIN = 1,
	VPN_TYPE_LOGIN_REPLY = 2,
	VPN_TYPE_ASSIGN = 3,
	VPN_TYPE_ASSIGN_REPLY = 4,
	VPN_TYPE_DATA = 5,
	VPN_TYPE_PING = 6,
	VPN_TYPE_PONG = 7
} VPNPacketType;

typedef struct PACKED _VPNKeyPacket {
	uint8_t key[32];
} VPNKeyPacket;

typedef struct PACKED _VPNAuthPacket {
	uint8_t token[512];
} VPNAuthPacket;

typedef struct PACKED _VPNAssignPacket {
	uint32_t ip;
	uint32_t subnet;
	uint32_t gateway;
	uint32_t mtu;
} VPNAssignPacket;

typedef struct PACKED _VPNDataPacket {
	uint8_t data[CHIPVPN_MAX_PACKET_SIZE];
} VPNDataPacket;

typedef struct PACKED _VPNPacketHeader {
	uint8_t type;
	uint32_t size;
} VPNPacketHeader;

typedef union _VPNPacketBody {
	VPNKeyPacket key_packet;
	VPNAuthPacket auth_packet;
	VPNAssignPacket dhcp_packet;
	VPNDataPacket data_packet;
} VPNPacketBody;

typedef struct PACKED _VPNPacket {
	VPNPacketHeader header;
	VPNPacketBody data;
} VPNPacket;

int vpnpacket_len(VPNPacket *packet);

#endif