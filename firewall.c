#include "firewall.h"
#include "packet.h"
#include <stdbool.h>
#include <netinet/in.h>

bool validate_packet(char *stream) {
	IPPacket *ip_hdr = (IPPacket*)(stream);

	if(ip_hdr->ip_p == IPPROTO_TCP) {
		int ip_size = 4 * ip_hdr->ihl;
		TCPHeader *tcp_hdr = (TCPHeader*)(stream + ip_size);
		if(tcp_hdr) {

		}
		return true;
	}
	if(ip_hdr->ip_p == IPPROTO_UDP) {
		int ip_size = 4 * ip_hdr->ihl;
		UDPHeader *udp_hdr = (UDPHeader*)(stream + ip_size);
		if(udp_hdr) {
			
		}
		return true;
	}
	if(ip_hdr->ip_p == IPPROTO_ICMP) {
		int ip_size = 4 * ip_hdr->ihl;
		ICMPHeader *icmp_hdr = (ICMPHeader*)(stream + ip_size);
		if(icmp_hdr) {
			
		}
		return true;
	}
	return false;
}