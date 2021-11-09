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

#include "firewall.h"
#include "packet.h"
#include <stdbool.h>
#include <netinet/in.h>

bool validate_inbound_packet(IPPacket *ip_hdr) {
	if(ip_hdr->ip_p == IPPROTO_TCP) {
		int ip_size = 4 * ip_hdr->ihl;
		TCPHeader *tcp_hdr = (TCPHeader*)(((char *)ip_hdr) + ip_size);
		if(tcp_hdr) {
			//printf("firewall allowed TCP traffic\n");
		}
		return true;
	}
	if(ip_hdr->ip_p == IPPROTO_UDP) {
		int ip_size = 4 * ip_hdr->ihl;
		UDPHeader *udp_hdr = (UDPHeader*)(((char *)ip_hdr) + ip_size);
		if(udp_hdr) {
			//printf("firewall allowed UDP traffic\n");
		}
		return true;
	}
	if(ip_hdr->ip_p == IPPROTO_ICMP) {
		int ip_size = 4 * ip_hdr->ihl;
		ICMPHeader *icmp_hdr = (ICMPHeader*)(((char *)ip_hdr) + ip_size);
		if(icmp_hdr) {
			//printf("firewall allowed ICMP traffic\n");
		}
		return true;
	}
	return false;
}

bool validate_outbound_packet(IPPacket *ip_hdr) {
	if(ip_hdr->ip_p == IPPROTO_TCP) {
		int ip_size = 4 * ip_hdr->ihl;
		TCPHeader *tcp_hdr = (TCPHeader*)(((char *)ip_hdr) + ip_size);
		if(tcp_hdr) {
			//printf("firewall allowed TCP traffic\n");
		}
		return true;
	}
	if(ip_hdr->ip_p == IPPROTO_UDP) {
		int ip_size = 4 * ip_hdr->ihl;
		UDPHeader *udp_hdr = (UDPHeader*)(((char *)ip_hdr) + ip_size);
		if(udp_hdr) {
			//printf("firewall allowed UDP traffic\n");
		}
		return true;
	}
	if(ip_hdr->ip_p == IPPROTO_ICMP) {
		int ip_size = 4 * ip_hdr->ihl;
		ICMPHeader *icmp_hdr = (ICMPHeader*)(((char *)ip_hdr) + ip_size);
		if(icmp_hdr) {
			//printf("firewall allowed ICMP traffic\n");
		}
		return true;
	}
	return false;
}