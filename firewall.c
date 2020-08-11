#include <stdbool.h>
#include <arpa/inet.h> 
#include "chipvpn.h"

bool validate_packet(char *stream) {
	IPPacket *ip_hdr = (IPPacket*)(stream);

	if(ip_hdr->ip_p == IPPROTO_TCP) {
		int ip_size = 4 * ip_hdr->ihl;
		TCPHeader *tcp_hdr = (TCPHeader*)(stream + ip_size);
		return true;
	}
	if(ip_hdr->ip_p == IPPROTO_UDP) {
		int ip_size = 4 * ip_hdr->ihl;
		UDPHeader *udp_hdr = (UDPHeader*)(stream + ip_size);
		return true;
	}
	if(ip_hdr->ip_p == IPPROTO_ICMP) {
		int ip_size = 4 * ip_hdr->ihl;
		ICMPHeader *icmp_hdr = (ICMPHeader*)(stream + ip_size);
		return true;
	}
	return false;
}