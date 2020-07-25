#include <stdbool.h>
#include <arpa/inet.h> 
#include "chipvpn.h"

bool validate_packet(IPPacket *packet) {
	if(ntohl(packet->dst_addr) == ntohl(inet_addr("1.1.1.1"))) {
		return false;
	}
	return true;
}